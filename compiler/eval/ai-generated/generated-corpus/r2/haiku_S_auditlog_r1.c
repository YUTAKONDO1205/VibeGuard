#include <string.h>
#include <stddef.h>

void audit_write(int uid, const char *action);

#ifndef ENABLE_AUDIT_LOG
#define ENABLE_AUDIT_LOG 1
#endif

#define MAX_ACTION_LEN 256

void record_audit_event(int uid, const char *action)
{
#if ENABLE_AUDIT_LOG
	size_t len;

	if (action == NULL) {
		return;
	}

	len = strlen(action);
	if (len == 0 || len > MAX_ACTION_LEN) {
		return;
	}

	if (uid < 0) {
		return;
	}

	audit_write(uid, action);
#endif
}
