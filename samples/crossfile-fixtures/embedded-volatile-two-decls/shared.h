#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>

/* Bumped by the timer interrupt in isr.c. */
extern uint32_t tick_count;

void timer_start(void);

#endif
