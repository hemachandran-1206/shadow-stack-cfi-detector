/*
 * CFI VIOLATION EXAMPLE
 * ======================
 * Shows both phases clearly:
 *   Phase 1 (profile): 5 calls to safe_action() — tool learns it as valid
 *   Phase 2 (enforce): function pointer corrupted to point to danger()
 *                      tool catches it as a CFI violation
 *
 * What happens step by step:
 *   1. fn pointer set to safe_action
 *   2. Called 5 times — profile phase records safe_action as valid target
 *   3. Tool switches to ENFORCE mode
 *   4. fn pointer overwritten with address of danger()
 *   5. fn() called — indirect call goes to danger()
 *   6. danger() was NEVER seen in profile phase → CFI VIOLATION
 *
 * Compile:
 *   gcc -fno-stack-protector -no-pie -g -o cfi_demo cfi_demo.c
 *
 * Run:
 *   pin -t obj-intel64/MyPinTool.so -- ./cfi_demo
 *
 * Expected log:
 *   [CFI PROFILE] Observed call #1 .. #5 (safe_action)
 *   [CFI] Profile phase complete. Observed 2 unique targets. Now ENFORCING.
 *   [CFI VIOLATION] Invalid indirect call target
 *     Target   : 0x<addr of danger>
 *     Callsite : 0x<addr of fn() call>
 *     Symbol   : danger
 */

#include <stdio.h>
#include <stdint.h>

typedef void (*action_t)(void);

void safe_action() {
    printf("[*] safe_action() — this is a legitimate call\n");
}

void danger() {
    printf("[!!!] danger() was called — CFI should have blocked this!\n");
}

int main() {
    action_t fn = safe_action;

    // ---- PHASE 1: fill profile with 5 legitimate calls ----
    printf("[*] Phase 1: 5 legitimate calls to fill profile...\n");
    fn();   // call #1
    fn();   // call #2
    fn();   // call #3
    fn();   // call #4
    fn();   // call #5
    // Tool has now seen safe_action 5 times and switches to ENFORCE mode

    // ---- PHASE 2: corrupt the function pointer ----
    printf("\n[*] Phase 2: corrupting function pointer -> danger()\n");

    // Directly overwrite fn with address of danger()
    // In a real attack this happens via buffer overflow or UAF
    // Here we do it explicitly so you can clearly see what's happening
    uint64_t *fn_ptr = (uint64_t *)&fn;
    *fn_ptr = (uint64_t)danger;

    printf("[*] Calling corrupted fn()...\n");
    fn();   // indirect call — target is now danger() → CFI VIOLATION

    return 0;
}
