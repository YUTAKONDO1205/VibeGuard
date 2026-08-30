#include <string.h>

/* Forward declaration of audit backend */
void audit_write(int uid, const char *action);

/*
 * record_audit_event: Log a privileged operation
 * @uid: User ID performing the action
 * @action: Description of the action
 *
 * Logs are conditionally compiled based on ENABLE_AUDIT_LOG.
 * If ENABLE_AUDIT_LOG is defined, audit_write() is called.
 * Otherwise, the function is a no-op.
 */
#ifdef ENABLE_AUDIT_LOG

void record_audit_event(int uid, const char *action)
{
	if (action == NULL) {
		return;
	}
	audit_write(uid, action);
}

#else /* ENABLE_AUDIT_LOG */

void record_audit_event(int uid, const char *action)
{
	(void)uid;
	(void)action;
}

#endif /* ENABLE_AUDIT_LOG */
