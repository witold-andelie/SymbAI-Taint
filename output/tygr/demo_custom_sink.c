#include <stdio.h>

/* Expected defect (GT annotation): tainted argv flows through main into the custom buffer sink store_record */
// @vuln: buffer_overflow argv -> store_record

/*
 * A custom unsafe buffer copy: a hand-rolled while loop with an unbounded write.
 * Key point: it calls no libc sink (no strcpy/memcpy/...), so pure
 * "function-name matching + structure heuristics (does it call a known sink?)" cannot detect it.
 * The only cue is the parameter types -- dst/src are both char* buffers (which the GNN can recover).
 */
void store_record(char *dst, char *src) {
    int i = 0;
    while (src[i] != '\0') {   /* no upper bound -> overflow if src is longer than dst */
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        store_record(buffer, argv[1]);   /* tainted argv[1] -> custom buffer sink */
        printf("%s\n", buffer);
    }
    return 0;
}
