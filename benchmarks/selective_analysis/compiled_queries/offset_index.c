/* Authored developer query: affine index transfer, queried at function entry. */
unsigned char case_buffer[8];

__attribute__((noinline))
void case_write(unsigned long index) {
    unsigned char *pointer = case_buffer;
    index += 4UL;
    pointer[index] = 0x41;
}

int main(void) {
    case_write(0);
    return 0;
}
