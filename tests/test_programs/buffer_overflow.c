/**
 * Buffer Overflow Test Program
 * Tests detection of various buffer overflow vulnerabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vulnerability 1: Stack buffer overflow via strcpy
void vuln_strcpy(const char *input) {
    char buffer[32];
    strcpy(buffer, input);  // No bounds checking
    printf("Buffer: %s\n", buffer);
}

// Vulnerability 2: Stack buffer overflow via strcat
void vuln_strcat(const char *input) {
    char buffer[32] = "Hello ";
    strcat(buffer, input);  // No bounds checking
    printf("Result: %s\n", buffer);
}

// Vulnerability 3: Heap buffer overflow
void vuln_heap(const char *input) {
    char *buffer = malloc(32);
    if (buffer) {
        strcpy(buffer, input);  // No bounds checking
        printf("Heap: %s\n", buffer);
        free(buffer);
    }
}

// Vulnerability 4: Off-by-one error
void vuln_offbyone(const char *input) {
    char buffer[32];
    int i;
    for (i = 0; i <= 32; i++) {  // Off-by-one: should be i < 32
        buffer[i] = input[i];
    }
    printf("Off-by-one: %s\n", buffer);
}

// Safe function: Uses bounds checking
void safe_copy(const char *input) {
    char buffer[32];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Safe: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    char *user_input = argv[1];

    // Test various buffer overflow vulnerabilities
    vuln_strcpy(user_input);
    vuln_strcat(user_input);
    vuln_heap(user_input);
    vuln_offbyone(user_input);
    safe_copy(user_input);

    return 0;
}
