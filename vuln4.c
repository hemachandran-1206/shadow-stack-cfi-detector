#include <stdio.h>

void legit_function() {
    printf("Safe function called\n");
}

int main() {
    void (*fptr)();

    // assign libc function
  fptr = (void (*)())((char*)printf + 5);  // invalid offset

    printf("Calling libc function via pointer:\n");
    fptr("Hello from printf\n");

    return 0;
}
