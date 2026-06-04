/**
 * Memory Vulnerability Test Program
 * Tests detection of memory-related vulnerabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vulnerability 1: Use-after-free
void vuln_use_after_free(const char *input) {
    char *buffer = malloc(64);
    if (buffer) {
        strcpy(buffer, input);
        printf("Buffer: %s\n", buffer);
        free(buffer);
        // Use-after-free: accessing freed memory
        printf("After free: %s\n", buffer);  // Vulnerability!
    }
}

// Vulnerability 2: Double free
void vuln_double_free(const char *input) {
    char *buffer = malloc(64);
    if (buffer) {
        strcpy(buffer, input);
        free(buffer);
        free(buffer);  // Double free!  // Vulnerability!
    }
}

// Vulnerability 3: Memory leak (not a security vuln, but bad practice)
void vuln_memory_leak(const char *input) {
    char *buffer = malloc(64);
    if (buffer) {
        strcpy(buffer, input);
        printf("Buffer: %s\n", buffer);
        // Missing free(buffer) - memory leak
    }
}

// Vulnerability 4: Uninitialized memory
void vuln_uninitialized(const char *input) {
    char buffer[64];
    // buffer is not initialized
    printf("Uninitialized: %s\n", buffer);  // May leak sensitive data
}

// Safe function: Proper memory management
void safe_memory(const char *input) {
    char *buffer = malloc(64);
    if (buffer) {
        strncpy(buffer, input, 63);
        buffer[63] = '\0';
        printf("Safe: %s\n", buffer);
        free(buffer);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    char *user_input = argv[1];

    // Test memory vulnerabilities
    vuln_use_after_free(user_input);
    // vuln_double_free(user_input);  // Commented to avoid crash
    vuln_memory_leak(user_input);
    vuln_uninitialized(user_input);
    safe_memory(user_input);

    return 0;
}
