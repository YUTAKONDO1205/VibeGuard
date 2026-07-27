#ifndef LEGACY_BOARD_H
#define LEGACY_BOARD_H

#include <stdint.h>

/*
 * The pre-refactor copy of the same declaration. Whether a translation unit
 * sees this one or the one in shared.h depends on the include path, which is
 * exactly what a scan of the sources does not have.
 */
extern uint32_t tick_count;

#endif
