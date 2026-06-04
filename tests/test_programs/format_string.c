/**
 * Format String Test Program
 * Tests detection of format string vulnerabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vulnerability 1: Direct format string
void vuln_printf_direct(const char *input) {
    printf(input);  // User-controlled format string
}

// Vulnerability 2: Format string via sprintf
void vuln_sprintf(const char *input) {
    char buffer[256];
    sprintf(buffer, input);  // User-controlled format string
    printf("Result: %s\n", buffer);
}

// Vulnerability 3: Format string with fprintf
void vuln_fprintf(const char *input) {
    fprintf(stdout, input);  // User-controlled format string
}

// Safe function: Uses format specifier
void safe_printf(const char *input) {
    printf("%s", input);  // Safe: uses format specifier
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    char *user_input = argv[1];

    // Test format string vulnerabilities
    vuln_printf_direct(user_input);
    vuln_sprintf(user_input);
    vuln_fprintf(user_input);
    safe_printf(user_input);

    return 0;
}
