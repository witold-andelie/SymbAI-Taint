/* A position in a seven by nine grid. */
#include "panel.h"

static inline uint64_t route_b_slot(uint64_t setting) {
    unsigned int column = (unsigned int)(setting % 7);
    unsigned int row = (unsigned int)((setting / 7) % 9);
    return row * 7 + column;
}
