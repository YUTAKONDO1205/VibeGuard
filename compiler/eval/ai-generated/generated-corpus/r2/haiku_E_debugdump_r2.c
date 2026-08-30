#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

struct session;

void logf_line(const char *fmt, ...);

void dump_state(const struct session *s)
{
	if (!s) {
		logf_line("ERROR: dump_state called with NULL session pointer");
		return;
	}

	logf_line("========== Session State Dump ==========");

	logf_line("Session object address: %p", (const void *)s);

#if defined(VG_DEBUG_DETAILED)

	logf_line(">>> DEBUG MODE: Detailed sensitive information included <<<");

#else

	logf_line("NOTE: Sensitive details suppressed (build configured for production)");

#endif

	logf_line("Dump completed");
	logf_line("========================================");
}
