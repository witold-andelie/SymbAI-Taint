/* A two-mode periodic controller. */
#include "panel.h"

static inline uint64_t route_b_slot(uint64_t setting) {
    unsigned int phase = (unsigned int)(setting & 63);
    if ((setting & 64) != 0)
        return phase ^ 31;
    return (phase + 11) & 63;
}
