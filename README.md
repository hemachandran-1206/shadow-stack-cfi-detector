## CFI-Shield — Buffer Overflow Detection using Shadow Stack and Control Flow Integrity

> **CS204 — Computer Architecture** | Kali Linux · Intel Pin · C · Python · HTML

A dynamic binary instrumentation tool built on **Intel Pin** that detects control flow hijacking attacks at runtime — without modifying source code or recompiling the target binary. The tool maintains a **shadow stack** to catch return address overwrites and enforces a **CFI profile** to detect indirect call hijacks, heap sprays, and use-after-free exploits.

---

## Why this matters

Modern exploits rarely crash programs directly. Instead, they corrupt memory — overwriting return addresses, function pointers, or vtable entries — to redirect execution to attacker-controlled code while the program continues to appear functional. Traditional defenses like stack canaries only catch one class of these attacks and can often be bypassed.

This project implements two complementary runtime defenses:

- **Shadow Stack** — maintains a trusted copy of return addresses outside the normal stack. Any mismatch at `RET` time signals a return address overwrite.
- **CFI Profile Enforcement** — observes which functions are legitimate indirect call targets during a profiling phase, then flags any call that lands outside that set during enforcement.

Together they cover the four main classes of control flow hijacking attacks used in real-world exploits.

---

## What this project achieves

| Attack class | Detection mechanism | Example binary |
|---|---|---|
| Stack buffer overflow → RET hijack | Shadow stack mismatch | `vuln1`, `vuln_ret_overwrite` |
| Use-after-free → indirect call hijack | CFI profile violation | `vuln_uaf`, `vuln3` |
| Heap spray → shellcode execution | CFI invalid target (out-of-exe) | `vuln_heapspray` |
| Race condition → callback hijack | CFI profile violation on thread | `vuln_thread` |
| Mid-function jump bypass | CFI entry-point validation | `vuln2`, `vuln4` |

Every violation is logged to `cfi_shadow.log` and structured into `cfi_report.json` with attack classification, severity, and fix suggestions — then visualised in a live web dashboard.

---

## Prerequisites

- **OS**: Kali Linux (tested) / Ubuntu 22.04+
- **Intel Pin** 4.2 (gcc-linux build)
- **GCC** 11+
- **Python** 3.10+
- **Make**
- A modern browser (Firefox / Chromium) for the dashboard

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/hemachandran-1206/shadow-stack-cfi-detector.git
cd shadow-stack-cfi-detector
```

### 2. Download and extract Intel Pin

```bash
mkdir -p ~/Documents/pin_kit && cd ~/Documents/pin_kit
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-4.2-99776-g21d818fa2-gcc-linux.tar.gz
tar -xzf pin-external-4.2-99776-g21d818fa2-gcc-linux.tar.gz
```

### 3. Build the Pin tool

```bash
cd /path/to/shadow-stack-cfi-detector
make
```

This compiles `MyPinTool.cpp` into `obj-intel64/MyPinTool.so`.

### 4. Build the vulnerable binaries (if not pre-built)

```bash
cd vulns/
make
```

---

## How it works

```
Target binary
     │
     ▼
Intel Pin (DBI framework)
     │
     ├── ImageLoad()        → records main exe bounds, function entry points, PLT range
     │
     ├── InstrumentRoutine()
     │     ├── CALL → RecordCall()       push return address to shadow stack
     │     ├── RET  → CheckRet()         compare actual vs shadow return address
     │     └── indirect CALL → CheckIndirectCall()
     │                          ├── profile phase: whitelist legitimate targets
     │                          └── enforce phase: flag anything not whitelisted
     │
     └── Fini()
           ├── writes cfi_shadow.log     (human-readable event log)
           └── writes cfi_report.json    (structured report with fix suggestions)
```

### Profile → Enforce transition

The tool watches the first **5 indirect calls** at each call site and records the set of legitimate target functions. After the threshold is reached, enforcement begins. Any subsequent indirect call to a target outside the whitelisted set triggers a `[CFI VIOLATION]`.

### Shadow stack

Every `CALL` instruction pushes the return address onto a per-thread shadow stack (protected by a mutex). Every `RET` instruction pops it and compares against the actual stack pointer. A mismatch means the return address on the real stack was overwritten — a `[SHADOW STACK VIOLATION]` is recorded.

---

## Project architecture

```
shadow-stack-cfi-detector/
├── pintool/
│   ├── MyPinTool.cpp        # Core Pin tool — shadow stack + CFI enforcement
│   ├── makefile             # Build config (points to Pin kit)
│   └── makefile.rules       # Pin build rules
│
├── vulns/
│   ├── vuln1.c              # Stack overflow (raw input, no bounds check)
│   ├── vuln2.c              # Mid-function indirect jump bypass
│   ├── vuln3.c              # Use-after-free via dangling pointer
│   ├── vuln4.c              # libc pointer arithmetic bypass
│   ├── vuln_ret_overwrite.c # Classic gets() return address overwrite
│   ├── vuln_uaf.c           # C++ use-after-free vtable hijack
│   ├── vuln_heapspray.c     # Heap spray → indirect call into heap
│   ├── vuln_thread.c        # Race condition → callback pointer hijack
│   ├── cfi_demo.c           # Controlled demo: function pointer corruption
│   └── shadow_demo.c        # Controlled demo: shadow stack validation
│
├── web/
│   ├── dashboard.html       # Live CFI results dashboard (Chart.js)
│   └── server.py            # Local HTTP server to serve dashboard + JSON
│
├── scripts/
│   └── parse_report.py      # Coloured terminal report parser
│
├── docs/
│   └── report.md            # Technical writeup
│
├── obj-intel64/             # Compiled Pin tool (.so) — generated by make
├── cfi_shadow.log           # Runtime event log — generated per run
├── cfi_report.json          # Structured JSON report — generated per run
└── README.md
```

---

## Running the tool

### Set the Pin path

```bash
export PIN=~/Documents/pin_kit/pin-external-4.2-99776-g21d818fa2-gcc-linux/pin
```

### Run against a single binary

```bash
cd shadow-stack-cfi-detector
rm -f cfi_report.json cfi_shadow.log
$PIN -t obj-intel64/MyPinTool.so -- ./vuln_ret_overwrite
cat cfi_shadow.log
```

### Run all binaries and parse reports

```bash
for v in cfi_demo vuln1 vuln2 vuln3 vuln4 vuln_ret_overwrite vuln_uaf vuln_heapspray vuln_thread; do
    echo "===== $v ====="
    rm -f cfi_report.json
    $PIN -t obj-intel64/MyPinTool.so -- ./$v 2>/dev/null
    python3 scripts/parse_report.py cfi_report.json
done
```

### Launch the web dashboard

```bash
# 1. Generate a report first
$PIN -t obj-intel64/MyPinTool.so -- ./vuln_uaf 2>/dev/null

# 2. Start the server
python3 web/server.py

# 3. Open in browser
#    http://localhost:8080/dashboard.html
```

---

## Demo

### Case 1 — Return address overwrite (`vuln_ret_overwrite`)

```
[*] Sending overflowed payload...
buf = AAAAAAAAAAAAAAAAAAAAAAAAA*@
[!!!] secret() was called — attacker redirected execution!

[SHADOW STACK VIOLATION] tid=0
  Expected : 0x40124c        ← legitimate return address
  Got      : 0x401196        ← secret() — attacker target

Shadow Stack Violations : 1
```

The `gets()` call wrote past the buffer boundary, overwriting the saved `RIP`. The shadow stack caught it immediately at `RET`.

---

### Case 2 — Use-after-free (`vuln_uaf`)

```
[*] real_method ×5
[!!!] evil_method via UAF

[CFI VIOLATION] tid=0
  Target   : 0x401150
  Symbol   : evil_method     ← never seen in profile phase
```

After `free()`, the memory was reallocated and the vtable pointer was overwritten to point to `evil_method`. The CFI profile had only whitelisted `real_method` — violation detected.

---

### Case 3 — Heap spray (`vuln_heapspray`)

```
[*] Spraying 64 heap chunks × 256 bytes...
[*] Indirect call into heap at 0x89139a0...

[CFI VIOLATION - INVALID TARGET] tid=0
  Target   : 0x89139a0       ← heap address, outside main exe
  Reason   : target outside main executable (libc/heap)
```

The target address falls in heap memory — not the code segment. The tool's bounds check flagged it before execution reached the shellcode.

---

### Case 4 — Thread callback hijack (`vuln_thread`)

```
[*] legitimate_work ×5
[!!!] evil_work — callback hijacked

[CFI VIOLATION] tid=1        ← caught on the attacker thread
  Target   : 0x4011f0
  Symbol   : evil_work
```

A race condition allowed a second thread to overwrite the callback pointer before the worker thread used it. Thread-aware CFI enforcement caught the violation on `tid=1`.

---

## JSON report sample

```json
{
  "summary": {
    "shadow_stack_violations": 1,
    "cfi_violations": 0,
    "total_violations": 1,
    "exit_code": 0
  },
  "violations": [
    {
      "id": 1,
      "type": "shadow_stack",
      "severity": "CRITICAL",
      "symbol": "secret",
      "expected_return": "0x40124c",
      "actual_return": "0x401196",
      "attack_description": "Return address overwrite — stack buffer overflow corrupted the saved return address",
      "fix_suggestion": "Use fgets instead of gets. Compile with -fstack-protector-strong. Enable ASLR and NX bit."
    }
  ]
}
```

---

## Real-world attack classes covered

| CVE class | CWE | Covered by |
|---|---|---|
| Stack buffer overflow | CWE-121 | Shadow stack |
| Heap-based overflow | CWE-122 | CFI profile |
| Use-after-free | CWE-416 | CFI profile |
| Return-oriented programming (ROP) | CWE-119 | Shadow stack |
| Heap spray | CWE-119 | CFI bounds check |
| Race condition (TOCTOU) | CWE-362 | Per-thread CFI |

---

## References and tools

- [Intel Pin — Dynamic Binary Instrumentation Framework](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html)
- [Intel Pin User Guide](https://software.intel.com/sites/landingpage/pintool/docs/98484/Pin/html/)
- [Control Flow Integrity — Abadi et al., 2005](https://research.microsoft.com/pubs/64250/ccs05.pdf) — the foundational CFI paper
- [Shadow Stack — Intel CET Overview](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
- [NIST NVD — National Vulnerability Database](https://nvd.nist.gov/)
- [Chart.js](https://www.chartjs.org/) — dashboard visualisation
- [Tabler Icons](https://tabler.io/icons) — dashboard icons

---

## License

MIT License — free to use for academic and educational purposes.

---

## Author

**Hemachandran**
[github.com/hemachandran-1206](https://github.com/hemachandran-1206)
CS204 — Computer Architecture
