/**
 * Test program with known vulnerabilities
 * Used for evaluating the OPM taint analysis system
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Vulnerable function 1: Buffer overflow via strcpy
void vulnerable_strcpy(const char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
    printf("Buffer: %s\n", buffer);
}

// Vulnerable function 2: Format string vulnerability
void vulnerable_printf(const char *input) {
    printf(input);  // User-controlled format string
}

// Vulnerable function 3: Command injection
void vulnerable_system(const char *input) {
    char command[256];
    sprintf(command, "echo %s", input);
    system(command);  // User-controlled command
}

// Vulnerable function 4: Stack buffer overflow
void vulnerable_stack(const char *input) {
    char buffer[32];
    gets(buffer);  // Dangerous function
}

// Vulnerable function 5: Heap buffer overflow
void vulnerable_heap(const char *input) {
    char *buffer = malloc(64);
    if (buffer) {
        strcpy(buffer, input);  // No bounds checking
        free(buffer);
    }
}

// Safe function: Uses bounded copy
void safe_function(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Buffer: %s\n", buffer);
}

// Main function with taint flow
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // Get user input (source)
    char *user_input = argv[1];

    // Taint flow 1: input -> strcpy
    vulnerable_strcpy(user_input);

    // Taint flow 2: input -> printf format string
    vulnerable_printf(user_input);

    // Taint flow 3: input -> system command
    vulnerable_system(user_input);

    // Taint flow 4: input -> gets (buffer overflow)
    vulnerable_stack(user_input);

    // Taint flow 5: input -> heap buffer overflow
    vulnerable_heap(user_input);

    // Safe function (no vulnerability)
    safe_function(user_input);

    return 0;
}
