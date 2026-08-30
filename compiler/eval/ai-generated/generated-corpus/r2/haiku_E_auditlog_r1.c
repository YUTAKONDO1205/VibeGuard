#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void audit_write(int uid, const char *action);

#ifndef ENABLE_AUDIT_LOG
#define ENABLE_AUDIT_LOG 1
#endif

void record_audit_event(int uid, const char *action)
{
#if ENABLE_AUDIT_LOG
    if (action == NULL) {
        return;
    }

    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
