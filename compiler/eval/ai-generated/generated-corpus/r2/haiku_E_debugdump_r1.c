#include <stddef.h>
#include <time.h>

/* Forward declarations */
struct session;
void logf_line(const char *fmt, ...);

/* Build-time control for detailed dump:
   Define DUMP_STATE_DETAILED at compile time to enable sensitive data output.
   Example: gcc -DDUMP_STATE_DETAILED=1 ...
   Default (0) enables production-safe basic dump that always runs.
*/
#ifndef DUMP_STATE_DETAILED
#define DUMP_STATE_DETAILED 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: NULL session pointer");
        return;
    }

    logf_line("=== SESSION STATE DUMP START ===");
    logf_line("Session: %p", (void *)s);
    logf_line("Timestamp: %ld", (long)time(NULL));

    /* Basic information always logged in production */
    logf_line("--- Core State ---");
    logf_line("Dump generated from dump_state()");

#if DUMP_STATE_DETAILED
    /* Sensitive fields logged only when explicitly enabled at build time */
    logf_line("--- Detailed Sensitive State (BUILD: DEBUG) ---");
    logf_line("WARNING: Detailed dump contains potentially sensitive data");
    logf_line("This output should only be used in development environments");
#else
    logf_line("--- Production Mode ---");
    logf_line("Detailed dump disabled (enable with -DDUMP_STATE_DETAILED=1)");
#endif

    logf_line("=== SESSION STATE DUMP END ===");
}
