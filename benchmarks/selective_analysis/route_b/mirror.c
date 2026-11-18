/* A mirrored position on a strip. */
#include "panel.h"

static inline uint64_t route_b_slot(uint64_t setting) {
    unsigned int position = (unsigned int)(setting & 127);
    return position < 64 ? position : 127 - position;
}
