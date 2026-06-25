#include <stdio.h>

void legit_function() {
    printf("Safe function called\n");
}

int main() {
    void (*fptr)();

    // assign libc function
    fptr = (void (*)())printf;

    printf("Calling libc function via pointer:\n");
    fptr("Hello from printf\n");

    return 0;
}
