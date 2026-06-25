#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <stack>
#include <unordered_set>
#include <map>
#include <set>
#include <vector>

using namespace std;

static ofstream logFile;

/* ════════════════════════════════════════════
   JSON Report — violation record
   ════════════════════════════════════════════ */

struct ViolationRecord {
    string type;         // "shadow_stack" | "cfi_indirect" | "cfi_invalid_target"
    string severity;     // "CRITICAL" | "HIGH"
    string attack;       // human-readable attack description
    string fix;          // suggested fix
    string symbol;       // function name if known
    ADDRINT target;
    ADDRINT callsite;
    ADDRINT expected;    // for shadow stack only
    ADDRINT got;         // for shadow stack only
    THREADID tid;
};

static vector<ViolationRecord> violations;

/* ════════════════════════════════════════════
   Shadow Stack — per-thread
   ════════════════════════════════════════════ */
static map<THREADID, stack<ADDRINT>> shadowStacks;
static map<THREADID, bool>           threadHijacked;
static PIN_MUTEX                     shadowMutex;
static UINT64                        shadowViolations = 0;

/* ════════════════════════════════════════════
   CFI — indirect call profile + enforce
   ════════════════════════════════════════════ */
static unordered_set<ADDRINT> observedTargets;
static bool   profilePhase     = true;
static UINT64 profileCallsSeen = 0;
static const  UINT64 PROFILE_THRESHOLD = 5;
static UINT64 cfiViolations = 0;

/* ════════════════════════════════════════════
   Main executable address range
   ════════════════════════════════════════════ */
static ADDRINT mainExeLow  = 0;
static ADDRINT mainExeHigh = 0;

/* ════════════════════════════════════════════
   Valid function entry points in main exe
   ════════════════════════════════════════════ */
static unordered_set<ADDRINT> validFunctionEntries;

/* ════════════════════════════════════════════
   PLT section range
   ════════════════════════════════════════════ */
static ADDRINT pltLow  = 0;
static ADDRINT pltHigh = 0;

static inline bool InPLT(ADDRINT addr)
{
    return (pltLow != 0) && (addr >= pltLow) && (addr < pltHigh);
}

static inline bool IsValidCodeTarget(ADDRINT addr)
{
    bool inMainExe = (mainExeLow != 0) &&
                     (addr >= mainExeLow) &&
                     (addr < mainExeHigh);
    if (!inMainExe || InPLT(addr))
        return false;

    if (!validFunctionEntries.empty())
        return validFunctionEntries.count(addr) > 0;

    return true;
}

/* ════════════════════════════════════════════
   Routines to skip entirely
   ════════════════════════════════════════════ */
static const set<string> SKIP_ROUTINES = {
    "_start",
    "__libc_csu_init",
    "__libc_csu_fini",
    "_init",
    "_fini",
    "frame_dummy",
    "__do_global_dtors_aux",
    "deregister_tm_clones",
    "register_tm_clones",
    "_dl_relocate_static_pie",
};

/* ════════════════════════════════════════════
   JSON helpers
   ════════════════════════════════════════════ */

static string JsonEscape(const string &s)
{
    string out;
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

static string AddrToHex(ADDRINT addr)
{
    ostringstream oss;
    oss << "0x" << hex << addr;
    return oss.str();
}

/* ════════════════════════════════════════════
   Thread lifecycle
   ════════════════════════════════════════════ */

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_MutexLock(&shadowMutex);
    shadowStacks[tid]   = stack<ADDRINT>();
    threadHijacked[tid] = false;
    PIN_MutexUnlock(&shadowMutex);
    logFile << "[THREAD START] tid=" << tid << endl;
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    logFile << "[THREAD END] tid=" << tid << endl;
}

/* ════════════════════════════════════════════
   Shadow Stack — CALL side
   ════════════════════════════════════════════ */

VOID RecordCall(ADDRINT retAddr, THREADID tid)
{
    PIN_MutexLock(&shadowMutex);
    if (!threadHijacked[tid])
        shadowStacks[tid].push(retAddr);
    PIN_MutexUnlock(&shadowMutex);
}

/* ════════════════════════════════════════════
   Shadow Stack — RET side
   ════════════════════════════════════════════ */

VOID CheckRet(ADDRINT rsp, THREADID tid)
{
    PIN_MutexLock(&shadowMutex);

    if (threadHijacked[tid]) {
        PIN_MutexUnlock(&shadowMutex);
        return;
    }

    stack<ADDRINT> &ss = shadowStacks[tid];
    if (ss.empty()) {
        PIN_MutexUnlock(&shadowMutex);
        return;
    }

    ADDRINT actualRet   = *reinterpret_cast<ADDRINT *>(rsp);
    ADDRINT expectedRet = ss.top();
    ss.pop();

    if (actualRet != expectedRet) {
        shadowViolations++;
        threadHijacked[tid] = true;
        while (!ss.empty()) ss.pop();

        logFile << "[SHADOW STACK VIOLATION] tid=" << tid << endl;
        logFile << "  Expected : 0x" << hex << expectedRet << endl;
        logFile << "  Got      : 0x" << hex << actualRet   << endl;

        // Record for JSON report
        string sym = RTN_FindNameByAddress(actualRet);
        ViolationRecord rec;
        rec.type     = "shadow_stack";
        rec.severity = "CRITICAL";
        rec.attack   = "Return address overwrite — stack buffer overflow corrupted the saved return address, redirecting execution to an attacker-controlled function";
        rec.fix      = "Use bounds-checked input functions (fgets instead of gets/scanf). Compile with -fstack-protector-strong to add stack canaries. Enable ASLR and NX bit.";
        rec.symbol   = sym.empty() ? "(unknown)" : sym;
        rec.target   = actualRet;
        rec.callsite = 0;
        rec.expected = expectedRet;
        rec.got      = actualRet;
        rec.tid      = tid;
        violations.push_back(rec);
    }

    PIN_MutexUnlock(&shadowMutex);
}

/* ════════════════════════════════════════════
   CFI — indirect call check
   ════════════════════════════════════════════ */

VOID CheckIndirectCall(ADDRINT target, ADDRINT callSite, THREADID tid)
{
    PIN_MutexLock(&shadowMutex);

    bool validTarget = IsValidCodeTarget(target);

    if (!validTarget) {
        cfiViolations++;
        string sym = RTN_FindNameByAddress(target);
        bool inMainExe = (mainExeLow != 0) &&
                         (target >= mainExeLow) &&
                         (target < mainExeHigh);
        string reason = inMainExe
            ? "target is mid-function address (not a valid entry point)"
            : "target outside main executable (libc/heap)";

        logFile << "[CFI VIOLATION - INVALID TARGET] tid=" << tid << endl;
        logFile << "  Target   : 0x" << hex << target   << endl;
        logFile << "  Callsite : 0x" << hex << callSite << endl;
        logFile << "  Reason   : " << reason            << endl;
        if (!sym.empty())
            logFile << "  Symbol   : " << sym << endl;

        // Record for JSON report
        ViolationRecord rec;
        rec.type     = "cfi_invalid_target";
        rec.severity = "CRITICAL";
        if (!inMainExe) {
            rec.attack = "Heap spray / libc redirect — attacker sprayed shellcode into heap memory and redirected an indirect call into it, bypassing code-segment restrictions";
            rec.fix    = "Enable W^X (NX bit) to prevent heap execution. Use Control Flow Guard (CFG) or hardware CET. Avoid storing raw function pointers; use type-safe abstractions.";
        } else {
            rec.attack = "Mid-function jump — attacker redirected an indirect call to the middle of a function, bypassing its prologue and security checks";
            rec.fix    = "Use fine-grained CFI that validates call targets against the exact function entry point set. Enable -fcf-protection=full at compile time.";
        }
        rec.symbol   = sym.empty() ? "(unknown)" : sym;
        rec.target   = target;
        rec.callsite = callSite;
        rec.expected = 0;
        rec.got      = 0;
        rec.tid      = tid;
        violations.push_back(rec);

        PIN_MutexUnlock(&shadowMutex);
        return;
    }

    if (profilePhase) {
        observedTargets.insert(target);
        profileCallsSeen++;

        logFile << "[CFI PROFILE] tid=" << tid
                << " call #"    << dec << profileCallsSeen
                << " target=0x" << hex << target
                << " (" << RTN_FindNameByAddress(target) << ")" << endl;

        if (profileCallsSeen >= PROFILE_THRESHOLD) {
            profilePhase = false;
            logFile << "[CFI] Profile done. "
                    << observedTargets.size()
                    << " targets recorded. Enforcing now." << endl;
        }

        PIN_MutexUnlock(&shadowMutex);
        return;
    }

    bool ok = (observedTargets.find(target) != observedTargets.end());
    PIN_MutexUnlock(&shadowMutex);

    if (!ok) {
        cfiViolations++;
        string sym = RTN_FindNameByAddress(target);

        logFile << "[CFI VIOLATION] tid=" << tid << endl;
        logFile << "  Target   : 0x" << hex << target   << endl;
        logFile << "  Callsite : 0x" << hex << callSite << endl;
        if (!sym.empty())
            logFile << "  Symbol   : " << sym << endl;

        // Record for JSON report
        ViolationRecord rec;
        rec.type     = "cfi_indirect";
        rec.severity = "HIGH";
        rec.attack   = "Indirect call hijack — a function pointer or vtable entry was overwritten (via buffer overflow, use-after-free, or type confusion) to redirect an indirect call to an attacker-controlled target";
        rec.fix      = "Use smart pointers (unique_ptr/shared_ptr) to prevent use-after-free. Mark vtables const. Enable -fsanitize=cfi at compile time for fine-grained CFI enforcement.";
        rec.symbol   = sym.empty() ? "(unknown)" : sym;
        rec.target   = target;
        rec.callsite = callSite;
        rec.expected = 0;
        rec.got      = 0;
        rec.tid      = tid;
        violations.push_back(rec);
    }
}

/* ════════════════════════════════════════════
   Instrumentation — routine level
   ════════════════════════════════════════════ */

VOID InstrumentRoutine(RTN rtn, VOID *v)
{
    IMG img = SEC_Img(RTN_Sec(rtn));
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
        return;

    string name = RTN_Name(rtn);
    if (SKIP_ROUTINES.count(name))
        return;

    RTN_Open(rtn);

    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        ADDRINT addr = INS_Address(ins);

        if (InPLT(addr)) {
            continue;
        }

        if (INS_IsCall(ins)) {
            ADDRINT retAddr = INS_Address(ins) + INS_Size(ins);

            bool targetInPLT = false;
            if (INS_IsDirectControlFlow(ins)) {
                ADDRINT tgt = INS_DirectControlFlowTargetAddress(ins);
                targetInPLT = InPLT(tgt);
            }

            if (!targetInPLT) {
                INS_InsertCall(ins, IPOINT_BEFORE,
                               (AFUNPTR)RecordCall,
                               IARG_ADDRINT, retAddr,
                               IARG_THREAD_ID,
                               IARG_END);
            }

            if (INS_IsIndirectControlFlow(ins) && !targetInPLT) {
                INS_InsertCall(ins, IPOINT_BEFORE,
                               (AFUNPTR)CheckIndirectCall,
                               IARG_BRANCH_TARGET_ADDR,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_THREAD_ID,
                               IARG_END);
            }
        }
        else if (INS_IsRet(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                           (AFUNPTR)CheckRet,
                           IARG_REG_VALUE, REG_STACK_PTR,
                           IARG_THREAD_ID,
                           IARG_END);
        }
    }

    RTN_Close(rtn);
}

/* ════════════════════════════════════════════
   Image load
   ════════════════════════════════════════════ */

VOID ImageLoad(IMG img, VOID *v)
{
    if (!IMG_IsMainExecutable(img)) return;

    mainExeLow  = IMG_LowAddress(img);
    mainExeHigh = IMG_HighAddress(img);

    logFile << "[IMAGE] Main exe: 0x" << hex << IMG_LowAddress(img)
            << " - 0x" << IMG_HighAddress(img) << endl;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            ADDRINT entry = RTN_Address(rtn);
            if (entry >= mainExeLow && entry < mainExeHigh && !InPLT(entry)) {
                validFunctionEntries.insert(entry);
                logFile << "[FUNC ENTRY] 0x" << hex << entry
                        << " (" << RTN_Name(rtn) << ")" << endl;
            }
        }
    }

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        string sname = SEC_Name(sec);
        if (sname == ".plt" || sname == ".plt.sec" || sname == ".plt.got") {
            ADDRINT lo = SEC_Address(sec);
            ADDRINT hi = lo + SEC_Size(sec);
            if (pltLow == 0 || lo < pltLow)  pltLow  = lo;
            if (hi > pltHigh)                 pltHigh = hi;
            logFile << "[PLT] " << sname
                    << " : 0x" << hex << lo << " - 0x" << hi << endl;
        }
    }
}

/* ════════════════════════════════════════════
   Write JSON report
   ════════════════════════════════════════════ */

VOID WriteJsonReport(INT32 exitCode)
{
    ofstream json("cfi_report.json");
    json << "{\n";
    json << "  \"summary\": {\n";
    json << "    \"shadow_stack_violations\": " << dec << shadowViolations << ",\n";
    json << "    \"cfi_violations\": "          << dec << cfiViolations    << ",\n";
    json << "    \"total_violations\": "        << dec << (shadowViolations + cfiViolations) << ",\n";
    json << "    \"cfi_observed_targets\": "    << dec << observedTargets.size() << ",\n";
    json << "    \"exit_code\": "               << exitCode << "\n";
    json << "  },\n";
    json << "  \"violations\": [\n";

    for (size_t i = 0; i < violations.size(); i++) {
        const ViolationRecord &r = violations[i];
        json << "    {\n";
        json << "      \"id\": "         << (i + 1) << ",\n";
        json << "      \"type\": \""     << JsonEscape(r.type)     << "\",\n";
        json << "      \"severity\": \"" << JsonEscape(r.severity) << "\",\n";
        json << "      \"thread_id\": "  << r.tid << ",\n";
        json << "      \"symbol\": \""   << JsonEscape(r.symbol)   << "\",\n";

        if (r.type == "shadow_stack") {
            json << "      \"expected_return\": \"" << AddrToHex(r.expected) << "\",\n";
            json << "      \"actual_return\": \""   << AddrToHex(r.got)      << "\",\n";
        } else {
            json << "      \"target\": \""   << AddrToHex(r.target)   << "\",\n";
            json << "      \"callsite\": \"" << AddrToHex(r.callsite) << "\",\n";
        }

        json << "      \"attack_description\": \"" << JsonEscape(r.attack) << "\",\n";
        json << "      \"fix_suggestion\": \""      << JsonEscape(r.fix)    << "\"\n";
        json << "    }";
        if (i + 1 < violations.size()) json << ",";
        json << "\n";
    }

    json << "  ]\n";
    json << "}\n";
    json.close();
}

/* ════════════════════════════════════════════
   Summary + JSON
   ════════════════════════════════════════════ */

VOID Fini(INT32 code, VOID *v)
{
    logFile << "\n========== SUMMARY ==========" << endl;
    logFile << "Shadow Stack Violations : " << dec << shadowViolations       << endl;
    logFile << "CFI Violations          : " << dec << cfiViolations          << endl;
    logFile << "CFI observed targets    : " << dec << observedTargets.size() << endl;
    logFile << "Exit code               : " << code                          << endl;
    logFile << "==============================" << endl;
    logFile.close();

    WriteJsonReport(code);
}

/* ════════════════════════════════════════════
   Entry point
   ════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);
    PIN_InitSymbols();
    PIN_MutexInit(&shadowMutex);

    logFile.open("cfi_shadow.log", std::ios::out | std::ios::trunc);

    IMG_AddInstrumentFunction(ImageLoad,         0);
    RTN_AddInstrumentFunction(InstrumentRoutine, 0);
    PIN_AddThreadStartFunction(ThreadStart,      0);
    PIN_AddThreadFiniFunction (ThreadFini,       0);
    PIN_AddFiniFunction       (Fini,             0);

    PIN_StartProgram();
    return 0;
}
