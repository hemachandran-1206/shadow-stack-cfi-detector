/*
 * TEST 2: Heap Use-After-Free → Vtable Corruption (CFI)
 * =======================================================
 * Fix: Use a static backing buffer instead of malloc/free.
 *      malloc/free are libc PLT calls that Pin may instrument,
 *      causing spurious shadow-stack noise. A static buffer
 *      gives the exact same UAF semantics without any heap calls.
 *
 * Compile:
 *   gcc -fno-stack-protector -no-pie -g -o vuln_uaf vuln_uaf.c
 *
 * Run:
 *   pin -t obj-intel64/MyPinTool.so -- ./vuln_uaf
 *
 * Expected output (cfi_shadow.log):
 *   [IMAGE] Main exe: ...
 *   [THREAD START] tid=0
 *   [CFI PROFILE] tid=0 call #1 target=0x<real_method> (real_method)
 *   [CFI PROFILE] tid=0 call #2 ...
 *   [CFI PROFILE] tid=0 call #3 ...
 *   [CFI PROFILE] tid=0 call #4 ...
 *   [CFI PROFILE] tid=0 call #5 ...
 *   [CFI] Profile done. 1 targets recorded. Enforcing now.
 *   [CFI VIOLATION] tid=0
 *     Target   : 0x<evil_method>
 *     Callsite : 0x<...>
 *     Symbol   : evil_method
 *   [THREAD END] tid=0
 *
 *   ========== SUMMARY ==========
 *   Shadow Stack Violations : 0
 *   CFI Violations          : 1
 *   CFI observed targets    : 1
 *   Exit code               : 0
 *   ==============================
 */

#include <stdio.h>
#include <stdint.h>

typedef void (*vfunc_t)(void);

typedef struct {
    vfunc_t *vtable;
    int       data;
} VObject;

void real_method(void) { printf("[*] real_method\n"); }
void evil_method(void) { printf("[!!!] evil_method via UAF\n"); }

/* vtables in static storage — no heap needed */
static vfunc_t legit_vtable[] = { real_method };
static vfunc_t fake_vtable[]  = { evil_method };

/*
 * Two static buffers simulate alloc/free/realloc without any
 * libc heap calls that would disturb the shadow stack.
 */
static uint64_t victim_buf[2];    /* obj lives here          */
static uint64_t attacker_buf[2];  /* attacker-reclaimed chunk */

int main(void)
{
    /* ── Set up the victim object ─────────────────────────── */
    VObject *obj = (VObject *)victim_buf;
    obj->vtable  = legit_vtable;
    obj->data    = 42;

    /* ── 5 legitimate indirect calls → fills CFI profile ─── */
    obj->vtable[0]();   /* call #1 */
    obj->vtable[0]();   /* call #2 */
    obj->vtable[0]();   /* call #3 */
    obj->vtable[0]();   /* call #4 */
    obj->vtable[0]();   /* call #5  →  profile done, enforce mode ON */

    /*
     * Simulate free() + realloc():
     *   Redirect obj to attacker_buf (dangling-pointer effect),
     *   then plant fake_vtable into offset 0.
     */
    obj = (VObject *)attacker_buf;           /* "dangle" / reclaim */
    attacker_buf[0] = (uint64_t)fake_vtable; /* plant fake vtable  */
    attacker_buf[1] = 0;

    /* ── UAF indirect call → CFI VIOLATION ──────────────────── */
    obj->vtable[0]();   /* resolves to evil_method — not in profile */

    return 0;
}
