#include <stdint.h>

extern const uint64_t safe_offsets[2];
extern const uint64_t outside_offsets[2];
unsigned char scalar_output[1024] = {1};
unsigned char table_output[8] = {1};
unsigned char outside_output[8] = {1};

__attribute__((noinline, used))
void typed_scalar_span(uint64_t index) {
    scalar_output[index] = 0x41;
}

__attribute__((noinline, used))
void typed_readonly_table(uint64_t index) {
    __asm__ volatile ("andq $1, %0" : "+r" (index));
    const uint64_t *cursor = &safe_offsets[index];
    __asm__ volatile ("" : "+r" (cursor));
    uint64_t offset = *cursor;
    table_output[offset] = 0x41;
}

__attribute__((noinline, used))
void typed_readonly_table_outside(uint64_t index) {
    __asm__ volatile ("andq $1, %0" : "+r" (index));
    const uint64_t *cursor = &outside_offsets[index];
    __asm__ volatile ("" : "+r" (cursor));
    uint64_t offset = *cursor;
    outside_output[offset] = 0x41;
}

int main(void) { return 0; }
