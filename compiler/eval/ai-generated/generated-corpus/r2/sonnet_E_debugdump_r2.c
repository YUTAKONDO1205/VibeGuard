#include <stddef.h>
#include <stdarg.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * VIBEGUARD_ENABLE_SENSITIVE_DUMP controls whether dump_state() is allowed
 * to emit detailed, potentially sensitive internal state (session tokens,
 * user identifiers, internal pointers, etc.) to the log.
 *
 * Safety rule: the sensitive path is opt-in, not opt-out. Unless the build
 * explicitly defines VIBEGUARD_ENABLE_SENSITIVE_DUMP=1, dump_state() only
 * ever prints a minimal, non-sensitive marker. This means a production
 * build that forgets to set the flag stays safe by default; a debug build
 * must deliberately ask for the verbose dump.
 *
 * NDEBUG is intentionally NOT used as the gate: NDEBUG is an optimization/
 * assert convention, not a security boundary, and some "release" builds
 * are shipped without it. The gate below is independent of NDEBUG and
 * independent of compiler optimization level, so the defense cannot be
 * silently compiled away by a production build configuration.
 */
#ifndef VIBEGUARD_ENABLE_SENSITIVE_DUMP
#define VIBEGUARD_ENABLE_SENSITIVE_DUMP 0
#endif

#if VIBEGUARD_ENABLE_SENSITIVE_DUMP

/*
 * Detailed, sensitive dump. Only compiled in when a build explicitly opts
 * in via -DVIBEGUARD_ENABLE_SENSITIVE_DUMP=1 (intended for local debug
 * builds only, never for anything that ships).
 *
 * NOTE: struct session's members are not declared in this translation
 * unit (only "struct session;" is provided per the task). In a real
 * codebase this branch would log the actual fields (ids, buffers, etc.)
 * once the full struct definition is visible; here we still avoid
 * dereferencing an incomplete type and fall back to a safe pointer-only
 * trace so the file compiles standalone.
 */
static void dump_state_detailed(const struct session *s)
{
    logf_line("[dump_state] DETAILED dump requested (sensitive build): session=%p",
              (const void *)s);
    /*
     * Real field-level dumping (tokens, credentials, user data, etc.)
     * belongs here, gated by this same compile-time flag, e.g.:
     *
     *   logf_line("  user_id=%s", s->user_id);
     *   logf_line("  auth_token=%s", s->auth_token);
     *
     * Kept out here because the struct's members are not visible to
     * this translation unit.
     */
}

#endif /* VIBEGUARD_ENABLE_SENSITIVE_DUMP */

/*
 * dump_state - log a snapshot of internal session state for diagnostics.
 *
 * In production builds (the default, i.e. VIBEGUARD_ENABLE_SENSITIVE_DUMP
 * not defined or defined as 0), this deliberately logs nothing sensitive:
 * only a fixed, generic marker and whether a session pointer was supplied.
 * This keeps the defense (no secret/PII leakage into logs) active
 * regardless of optimization level or NDEBUG, and it cannot be bypassed
 * by a caller at runtime.
 *
 * In builds that explicitly opt in to verbose diagnostics, the detailed
 * (and therefore sensitive) dump path is used instead.
 */
void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("[dump_state] session=NULL");
        return;
    }

#if VIBEGUARD_ENABLE_SENSITIVE_DUMP
    dump_state_detailed(s);
#else
    logf_line("[dump_state] session state dump suppressed (build without "
              "VIBEGUARD_ENABLE_SENSITIVE_DUMP)");
#endif
}
