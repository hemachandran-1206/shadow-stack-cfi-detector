/*
 * TEST 1: Return Address Overwrite
 * ================================
 * What happens:
 *   vulnerable() has a char buf[16].
 *   We overflow it with strcpy to overwrite the saved return address
 *   on the stack, redirecting it to secret().
 *
 * What YOUR TOOL catches:
 *   [SHADOW STACK VIOLATION]
 *   The return address on the real stack no longer matches
 *   what was recorded in the shadow stack at call time.
 *
 * Compile:
 *   gcc -fno-stack-protector -no-pie -g -o vuln_ret_overwrite vuln_ret_overwrite.c
 *
 * Run:
 *   pin -t obj-intel64/MyPinTool.so -- ./vuln_ret_overwrite
 */

#include <stdio.h>
#include <string.h>

void secret() {
    printf("[!!!] secret() was called — attacker redirected execution!\n");
}

void vulnerable(char *input) {
    char buf[16];
    strcpy(buf, input);    // no bounds check — overflows saved return address
    printf("buf = %s\n", buf);
}

int main() {
    // Stack layout inside vulnerable():
    //   buf[16]  |  saved RBP[8]  |  saved RIP[8]
    char payload[33];
    memset(payload, 'A', 24);              // fill buf[16] + saved RBP[8]
    void *target = (void *)secret;
    memcpy(payload + 24, &target, 8);      // overwrite saved RIP -> secret()
    payload[32] = '\0';

    printf("[*] Sending overflowed payload...\n");
    vulnerable(payload);

    return 0;
}
