/**
 * Command Injection Test Program
 * Tests detection of command injection vulnerabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vulnerability 1: Direct command injection via system()
void vuln_system(const char *input) {
    char command[256];
    sprintf(command, "echo %s", input);
    system(command);  // User-controlled command
}

// Vulnerability 2: Command injection via popen()
void vuln_popen(const char *input) {
    char command[256];
    snprintf(command, sizeof(command), "ls %s", input);
    FILE *fp = popen(command, "r");  // User-controlled command
    if (fp) {
        char result[256];
        while (fgets(result, sizeof(result), fp)) {
            printf("%s", result);
        }
        pclose(fp);
    }
}

// Vulnerability 3: Command injection via exec()
void vuln_exec(const char *input) {
    char *args[] = {"/bin/sh", "-c", NULL, NULL};
    char command[256];
    snprintf(command, sizeof(command), "echo %s", input);
    args[2] = command;
    execv(args[0], args);  // User-controlled command
}

// Safe function: Uses execve with controlled arguments
void safe_exec(const char *input) {
    char *args[] = {"/bin/echo", NULL, NULL};
    args[1] = (char *)input;
    execv(args[0], args);  // Safe: input is argument, not command
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    char *user_input = argv[1];

    // Test command injection vulnerabilities
    vuln_system(user_input);
    // vuln_popen(user_input);  // Commented to avoid execution
    // vuln_exec(user_input);   // Commented to avoid execution
    // safe_exec(user_input);   // Commented to avoid execution

    return 0;
}
