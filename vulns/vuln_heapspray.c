/*
 * TEST 3: Heap Spray + Indirect Call into Heap (CFI)
 * ====================================================
 * Attack:
 *   64 heap chunks of 256 bytes are allocated and filled with 0x90
 *   (NOP instruction on x86). The attacker then crafts a function
 *   pointer pointing into the middle of one of those chunks (offset
 *   128 of chunk 32). That address is never a function entry point
 *   and was never observed during the profile phase. Calling through
 *   that pointer simulates shellcode execution via heap spray.
 *
 * What MyPinTool catches:
 *   5 legitimate indirect calls to normal_func_a fill the profile
 *   phase. Tool switches to enforce mode.
 *   The heap address is not in observedTargets → CFI violation.
 *   The symbol field will be empty because heap has no symbol.
 *
 * Compile:
 *   gcc -fno-stack-protector -no-pie -g -z execstack -o vuln_heapspray vuln_heapspray.c
 *
 * Run:
 *   pin -t obj-intel64/MyPinTool.so -- ./vuln_heapspray
 *
 * Expected output (cfi_shadow.log):
 *   [CFI PROFILE] tid=0 call #1 target=0x<normal_func_a addr> (normal_func_a)
 *   ... (5 times)
 *   [CFI] Profile done. 1 targets recorded. Enforcing now.
 *   [CFI VIOLATION] tid=0
 *     Target   : 0x<heap address — middle of sprayed chunk>
 *     Callsite : 0x<addr of evil() call in main>
 *     (no Symbol line — heap has no symbol)
 *
 *   ========== SUMMARY ==========
 *   Shadow Stack Violations : 0
 *   CFI Violations          : 1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef void (*fn_t)(void);

#define SPRAY_COUNT 64
#define SPRAY_SIZE  256

void normal_func_a() { printf("[*] normal_func_a\n"); }

int main() {
    void *sprayed[SPRAY_COUNT];

    /* spray heap with NOPs */
    for (int i = 0; i < SPRAY_COUNT; i++) {
        sprayed[i] = malloc(SPRAY_SIZE);
        memset(sprayed[i], 0x90, SPRAY_SIZE);
    }

    /* 5 legitimate indirect calls — fills CFI profile phase */
    fn_t fn = normal_func_a;
    fn(); fn(); fn(); fn(); fn();
    /* tool is now in enforce mode — only normal_func_a in observed set */

    /* craft pointer into middle of a heap chunk — pure heap, never a function */
    uint8_t *heap_target = (uint8_t *)sprayed[32] + 128;
    fn_t evil = (fn_t)heap_target;
    evil();   /* CFI VIOLATION — heap addr not in observedTargets */

    for (int i = 0; i < SPRAY_COUNT; i++) free(sprayed[i]);
    return 0;
}
