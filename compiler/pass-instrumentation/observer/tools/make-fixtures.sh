#!/bin/bash
# Measurement inputs for the observer, written into the lab rather than kept
# beside the sources: a fixture under compiler/ is a measurement input in the
# published tree, which the boundary guard fails on. This script IS the
# fixture and is reviewable as one.
set -u
LAB=${OBS_LAB:-$HOME/vg-lab/pass-observer}
mkdir -p "$LAB/fixtures/erasure" "$LAB/rq2-fixtures"
cat > "$LAB/fixtures/erasure/main.c" <<'FIXTURE_EOF'
void handle_request(void);
void wipe_kept(void);
void handle_request_bzero(void);

int main(void) {
    handle_request();
    wipe_kept();
    handle_request_bzero();
    return 0;
}
FIXTURE_EOF
cat > "$LAB/fixtures/erasure/manifest.json" <<'FIXTURE_EOF'
{
  "schemaVersion": "manifest-v0",
  "fixtureId": "erasure",
  "title": "Secret wipe removed as a dead store",
  "role": "measurement",
  "sources": { "target": "target.c", "opaque": "opaque.c", "main": "main.c" },
  "axes": {
    "opt": ["-O0", "-O1", "-O2", "-O3"],
    "mitigation": { "name": "-fno-builtin-memset", "off": [], "on": ["-fno-builtin-memset"] },
    "compiler": ["clang-18", "gcc-13"]
  },
  "referenceConfig": "clang-18/-O0/mit-off",
  "properties": [
    {
      "propertyId": "erasure.wipe",
      "kind": "Must-Survive",
      "family": "erasure",
      "targetFn": "handle_request",
      "oracleControlFn": "wipe_kept",
      "_note_handle_request_bzero":
        "target.c also defines handle_request_bzero, the recommended fix. It is not a measured control here — the fix is exercised by the closure stage, which applies the remediation below and follows the result to the linked binary. Declaring it as a control would have claimed a measurement that nothing performs.",
      "effectSymbols": ["llvm.memset", "memset", "explicit_bzero", "bzero", "__memset_chk"],
      "opaqueSymbols": ["get_secret", "consume"],
      "subjectSymbols": ["get_secret", "consume"],
      "sourceAnchor": { "file": "target.c", "line": 13, "expect": "memset(secret, 0, sizeof secret)" },
      "remediation": {
        "ruleId": "VG-MEM-006",
        "file": "target.c",
        "line": 13,
        "from": "memset(secret, 0, sizeof secret);",
        "to": "explicit_bzero(secret, sizeof secret);"
      },
      "plannedCheckpoints": ["preprocess", "ast", "ir-pre", "ir-post", "asm", "artifact"],
      "hypothesis": {
        "firstLossStage": "ir-pass",
        "note": "Recorded earlier as DSEPass. A mismatch is a result to report, not a bug to fix by moving the predicate."
      }
    }
  ]
}
FIXTURE_EOF
cat > "$LAB/fixtures/erasure/opaque.c" <<'FIXTURE_EOF'
/* Producer and consumer in a separate translation unit: this is what forces the
 * secret to be materialised on the stack. */
volatile unsigned char sink;

void get_secret(unsigned char *out, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(i * 7u + 1u);
}

void consume(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}
FIXTURE_EOF
cat > "$LAB/fixtures/erasure/target.c" <<'FIXTURE_EOF'
#define _GNU_SOURCE 1
#include <string.h>

void get_secret(unsigned char *out, unsigned long n);   /* other TU */
void consume(const unsigned char *p, unsigned long n);  /* other TU */

/* Subject. The wipe is the last use of the buffer, so it is a dead store and
 * the optimiser is free to delete it. */
void handle_request(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}

/* Oracle control. The wipe is read afterwards, so it is observable and cannot
 * be deleted at any optimisation level. Its purpose is to show that the oracle
 * can still see a wipe in whatever form the compiler chose for this
 * configuration — at -O1 and above that form is inline zeroing, not a call. */
void wipe_kept(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    consume(secret, sizeof secret);
}

/* Survival control. The recommended fix: a wipe the compiler is not allowed to
 * remove even though it is the last use. */
void handle_request_bzero(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    explicit_bzero(secret, sizeof secret);
}
FIXTURE_EOF
cat > "$LAB/rq2-fixtures/wipe.c" <<'FIXTURE_EOF'
#define _GNU_SOURCE 1
#include <string.h>

void get_secret(unsigned char *out, unsigned long n);   /* other TU */
void consume(const unsigned char *p, unsigned long n);  /* other TU */

/* Subject. The wipe is the last use of the buffer, so it is a dead store and
 * the optimiser is free to delete it. */
void handle_request(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}

/* Oracle control. The wipe is read afterwards, so it is observable and cannot
 * be deleted at any optimisation level. Its purpose is to show that the oracle
 * can still see a wipe in whatever form the compiler chose for this
 * configuration — at -O1 and above that form is inline zeroing, not a call. */
void wipe_kept(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    consume(secret, sizeof secret);
}

/* Survival control. The recommended fix: a wipe the compiler is not allowed to
 * remove even though it is the last use. */
void handle_request_bzero(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    explicit_bzero(secret, sizeof secret);
}
FIXTURE_EOF
echo "fixtures written to $LAB"
