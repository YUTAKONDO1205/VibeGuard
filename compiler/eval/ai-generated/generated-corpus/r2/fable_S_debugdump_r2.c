#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * Detailed dump of sensitive internal state.
 *
 * The detailed dump is compiled in ONLY when VG_DEBUG_DUMP is defined at
 * build time (e.g. -DVG_DEBUG_DUMP for internal debug builds). In any build
 * that does not define it, the sensitive branch is removed by the
 * preprocessor -- it is not merely skipped at run time -- so no secret can
 * ever reach the log through a release binary, and no dead code carrying
 * secret-formatting logic is even present in the object file.
 */

#if defined(VG_DEBUG_DUMP)

/*
 * Accessors for the sensitive fields live in the translation unit that owns
 * the real definition of `struct session`. Here the type is incomplete, so
 * we only forward its address. These are the extent of what the detailed
 * dump is allowed to touch; keeping them behind functions means the secret
 * material never has to be materialized into a local buffer in this file.
 */
void session_dump_sensitive(const struct session *s);

#endif /* VG_DEBUG_DUMP */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session dump: <null session>");
        return;
    }

    /*
     * Non-sensitive summary is always safe to emit. It intentionally does
     * not include any credential, token, key, or personal data -- only that
     * a session object exists. Note we do NOT log the pointer value either,
     * to avoid leaking address-layout information usable for exploitation.
     */
    logf_line("session dump: session active");

#if defined(VG_DEBUG_DUMP)
    /*
     * Debug-only detailed dump. Compiled out entirely in release builds.
     */
    session_dump_sensitive(s);
#endif /* VG_DEBUG_DUMP */
}
