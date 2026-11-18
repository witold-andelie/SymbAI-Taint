/* A fixed palette lookup. */
#include "panel.h"

static inline uint64_t route_b_slot(uint64_t setting) {
    static const unsigned char slots[8] = {3, 12, 27, 44, 7, 19, 53, 60};
    return slots[setting & 7];
}
