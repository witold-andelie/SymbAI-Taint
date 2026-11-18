#include <stdint.h>

volatile unsigned char route_b_output[64];

static __attribute__((always_inline)) inline uint64_t route_b_slot(uint64_t setting);

__attribute__((noinline, used))
void route_b_step(uint64_t setting) {
    route_b_output[route_b_slot(setting)] = 0x41;
}

#ifdef ROUTE_B_SELF_CHECK
int main(void) {
    for (uint64_t setting = 0; setting < 256; ++setting) {
        if (route_b_slot(setting) >= sizeof route_b_output)
            return 1;
    }
    return 0;
}
#else
int main(void) {
    return 0;
}
#endif
