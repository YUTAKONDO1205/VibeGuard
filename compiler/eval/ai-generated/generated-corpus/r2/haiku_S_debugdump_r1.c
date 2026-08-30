#include <stdio.h>
#include <stddef.h>
#include <time.h>

extern void logf_line(const char *fmt, ...);

#ifndef DEBUG_DETAILED_DUMP
#define DEBUG_DETAILED_DUMP 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("[dump_state] ERROR: session pointer is NULL");
        return;
    }

    logf_line("[dump_state] === Session State Dump ===");

    logf_line("[dump_state] Session address: %p", (void *)s);

    if (s->id != NULL) {
        logf_line("[dump_state] Session ID: %s", s->id);
    } else {
        logf_line("[dump_state] Session ID: (null)");
    }

    if (s->created_at != 0) {
        struct tm *tm_info = localtime(&s->created_at);
        char time_buf[64];
        if (tm_info != NULL) {
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            logf_line("[dump_state] Created at: %s", time_buf);
        }
    }

    logf_line("[dump_state] State flags: 0x%08x", s->flags);
    logf_line("[dump_state] Reference count: %d", s->ref_count);

    if (s->user_id != NULL) {
        logf_line("[dump_state] User ID: %s", s->user_id);
    } else {
        logf_line("[dump_state] User ID: (null)");
    }

    logf_line("[dump_state] Session timeout: %u seconds", s->timeout);
    logf_line("[dump_state] Last activity: %ld seconds ago",
              (long)(time(NULL) - s->last_activity));

#if DEBUG_DETAILED_DUMP
    logf_line("[dump_state] === Detailed Debug Information ===");

    if (s->auth_token != NULL) {
        logf_line("[dump_state] Auth token (first 8 chars): %.8s...", s->auth_token);
    } else {
        logf_line("[dump_state] Auth token: (null)");
    }

    logf_line("[dump_state] Permissions mask: 0x%016lx", s->permissions);
    logf_line("[dump_state] Session context size: %zu bytes", s->context_size);

    if (s->client_addr != NULL) {
        logf_line("[dump_state] Client address: %s", s->client_addr);
    } else {
        logf_line("[dump_state] Client address: (null)");
    }

    logf_line("[dump_state] Internal state: 0x%08x", s->internal_state);
    logf_line("[dump_state] Error code: %d", s->error_code);
    logf_line("[dump_state] Retry count: %d", s->retry_count);

#else
    logf_line("[dump_state] (detailed debug output disabled)");
#endif

    logf_line("[dump_state] === End of Session State Dump ===");
}
