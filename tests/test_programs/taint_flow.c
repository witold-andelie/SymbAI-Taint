/**
 * Test program with complex taint flows
 * Tests the OPM system's ability to track taint through data flow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global buffer (potential sink)
char global_buffer[256];

// Function that processes data
char* process_data(const char *input) {
    size_t len = strlen(input);
    char *processed = malloc(len + 1);
    if (processed) {
        strcpy(processed, input);
    }
    return processed;
}

// Function that copies to global buffer
void copy_to_global(const char *input) {
    strcpy(global_buffer, input);  // Potential overflow
}

// Function with indirect taint flow
void indirect_flow(const char *input) {
    char temp[128];
    char *ptr = temp;

    // Copy to temp buffer
    strcpy(temp, input);

    // Copy from temp to another buffer
    char dest[64];
    strcpy(dest, ptr);  // Overflow if input > 64 bytes

    printf("Dest: %s\n", dest);
}

// Function with conditional taint flow
void conditional_flow(const char *input, int flag) {
    char buffer[64];

    if (flag) {
        strcpy(buffer, input);  // Vulnerable path
    } else {
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    }

    printf("Buffer: %s\n", buffer);
}

// Function with loop-based taint flow
void loop_flow(const char *input) {
    char buffer[32];
    int i;

    // Copy character by character
    for (i = 0; input[i] != '\0' && i < sizeof(buffer) - 1; i++) {
        buffer[i] = input[i];
    }
    buffer[i] = '\0';

    printf("Buffer: %s\n", buffer);
}

// Function with pointer arithmetic
void pointer_flow(const char *input) {
    char buffer[64];
    char *ptr = buffer;

    // Copy using pointer arithmetic
    while (*input) {
        *ptr++ = *input++;
    }
    *ptr = '\0';

    printf("Buffer: %s\n", buffer);
}

// Main function
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    char *user_input = argv[1];

    // Test 1: Direct taint flow
    printf("Test 1: Direct flow\n");
    copy_to_global(user_input);

    // Test 2: Indirect taint flow
    printf("Test 2: Indirect flow\n");
    indirect_flow(user_input);

    // Test 3: Conditional taint flow
    printf("Test 3: Conditional flow\n");
    conditional_flow(user_input, 1);

    // Test 4: Loop-based taint flow
    printf("Test 4: Loop flow\n");
    loop_flow(user_input);

    // Test 5: Pointer-based taint flow
    printf("Test 5: Pointer flow\n");
    pointer_flow(user_input);

    // Test 6: Processed data
    printf("Test 6: Processed data\n");
    char *processed = process_data(user_input);
    if (processed) {
        printf("Processed: %s\n", processed);
        free(processed);
    }

    return 0;
}
