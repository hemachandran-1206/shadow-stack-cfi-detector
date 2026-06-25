#include <stdio.h>
#include <stdint.h>

void legit_function() {
    printf("Safe function called\n");
}

void evil_function() {
    printf("Hacked!\n");
}

int main() {
    void (*fptr)() = legit_function;

    printf("Before corruption:\n");
    fptr();

    // simulate corruption: arbitrary address inside exe
    fptr = (void (*)())0x401195;

    printf("After corruption:\n");
    fptr();

    return 0;
}
