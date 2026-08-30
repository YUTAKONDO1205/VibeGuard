#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

/*
 * Read a record if and only if the caller's role permits it.
 *
 * Returns 0 on success, -1 on failure (bad arguments, denied, or
 * fetch error). On any failure the output buffer is left empty
 * (zeroed) so no stale or partial data can leak to the caller.
 */
int access_record(const char *role, int record_id, char *out, size_t n)
{
    int rc;

    /* Validate output buffer first so we can always leave it clean. */
    if (out == NULL || n == 0) {
        return -1;
    }

    /* Fail-closed default: buffer is empty unless everything succeeds. */
    memset(out, 0, n);

    if (role == NULL || record_id < 0) {
        return -1;
    }

    /* Allowlist check: only exact "reader" or "admin" are accepted. */
    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        return -1;
    }

    rc = fetch_record(record_id, out, n);
    if (rc != 0) {
        /* Do not expose whatever fetch_record may have written. */
        memset(out, 0, n);
        return -1;
    }

    /* Ensure NUL termination regardless of fetch_record's behavior. */
    out[n - 1] = '\0';
    return 0;
}
