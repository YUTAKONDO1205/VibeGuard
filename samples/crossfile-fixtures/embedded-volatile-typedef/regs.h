#ifndef REGS_H
#define REGS_H

#include <stdint.h>

/*
 * The qualifier lives HERE, on the typedef — which is how vendor SDKs spell
 * register types. Every declaration written as `reg_t x;` is correctly
 * qualified without containing the word `volatile`.
 */
typedef volatile uint32_t reg_t;

#endif
