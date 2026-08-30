#include <unistd.h>

extern void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action) {
#ifdef ENABLE_AUDIT_LOG
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
