#include <stdio.h>

void audit_write(int uid, const char *action);

#ifdef AUDIT_ENABLED

void record_audit_event(int uid, const char *action)
{
    if (action == NULL) {
        return;
    }

    if (uid < 0) {
        return;
    }

    audit_write(uid, action);
}

#else

void record_audit_event(int uid, const char *action)
{
    (void)uid;
    (void)action;
}

#endif
