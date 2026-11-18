/* A saturating control value. */
#include "panel.h"

static inline uint64_t route_b_slot(uint64_t setting) {
    return setting < 64 ? setting : 63;
}
