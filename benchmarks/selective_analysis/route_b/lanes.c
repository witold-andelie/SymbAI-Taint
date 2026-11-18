/* Four interleaved display lanes. */
#include "panel.h"

static inline uint64_t route_b_slot(uint64_t setting) {
    return ((setting >> 2) & 15) * 4 + (setting & 3);
}
