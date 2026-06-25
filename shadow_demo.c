/*
 * TEST 1: Shadow Stack Violation
 * ================================
 * Attack:
 *   vulnerable() directly overwrites its own return address on the
 *   real stack using __builtin_frame_address(0). It replaces the
 *   legitimate return address (back to main) with the address of
 *   secret(). When vulnerable() executes RET, the CPU jumps to
 *   secret() instead of main().
 *
 * What MyPinTool catches:
 *   On the CALL to vulnerable(), RecordCall() saves the real return
 *   address (back to main) onto the shadow stack.
 *
 *   On the RET of vulnerable(), CheckRet() reads *RSP from the real
 *   stack — which now says secret() — and compares it against the
 *   shadow stack — which still says main(). Mismatch → violation.
 *
 *   After logging the violation, MyPinTool FLUSHES the thread's
 *   shadow stack entirely. This means when secret() later executes
 *   its own RET, CheckRet() sees an empty shadow stack and returns
 *   immediately — no second spurious violation.
 *
 * Compile:
 *   gcc -fno-stack-protector -no-pie -g -o shadow_demo shadow_demo.c
 *
 * Run:
 *   /home/ubuntu/pin/pin -t obj-intel64/MyPinTool.so -- ./shadow_demo
 *
 * Expected output (cfi_shadow.log):
 *   [IMAGE] Main exe: 0x400000 - 0x40219b
 *   [THREAD START] tid=0
 *   [SHADOW STACK VIOLATION] tid=0
 *     Expected : 0x<address inside main()>
 *     Got      : 0x<address of secret()>
 *   [THREAD END] tid=0
 *
 *   ========== SUMMARY ==========
 *   Shadow Stack Violations : 1
 *   CFI Violations          : 0
 *   CFI observed targets    : 0
 *   Exit code               : 0
 *   ==============================
 */

#include <stdio.h>
#include <stdint.h>

void secret() {
    printf("[!!!] secret() was called — return address was hijacked!\n");
}

void vulnerable() {
    /*
     * __builtin_frame_address(0) returns the current frame pointer (RBP).
     * On x86-64 the stack frame layout at this point is:
     *   [RBP + 0] = saved RBP   (frame[0])
     *   [RBP + 8] = return addr (frame[1])  ← we overwrite this
     */
    uint64_t *frame = (uint64_t *)__builtin_frame_address(0);
    frame[1] = (uint64_t)secret;   /* overwrite return address on real stack */
}

int main() {
    vulnerable();
    /* Control never reaches here — vulnerable() returns to secret() instead */
    printf("[*] Back in main (you will NOT see this)\n");
    return 0;
}
