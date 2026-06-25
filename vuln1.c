#include <stdio.h>
#include <string.h>

void secret_function() {
    printf("This should never run normally.\n");
}

void vulnerable() {
    char buffer[16];
    printf("Enter input: ");
    gets(buffer);
    printf("Returning from vulnerable...\n");
}

int main() {
    vulnerable();
    printf("Program finished normally.\n");
    return 0;
}
