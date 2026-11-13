/* Direct-index mechanism, compiled with DWARF for one integration check.
 * The analysis query's entry is probe_write with index in [0, 15].
 * This file is not an independent evaluation set or a runtime witness.
 */
unsigned char probe_buffer[8];

__attribute__((noinline))
void probe_write(unsigned long index) {
    unsigned char *pointer = probe_buffer;
    pointer[index] = 0x41;
}

int main(void) {
    probe_write(0);
    return 0;
}
