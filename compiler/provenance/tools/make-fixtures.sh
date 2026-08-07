#!/usr/bin/env bash
# Write the rebuild fixture into a scratch directory.
#
#   bash make-fixtures.sh <dir>
#
# The two sources used to live under compiler/provenance/fixtures/, and that was
# a rule violation rather than a layout choice: measurement inputs do not belong
# in the published tree (they accrete per-machine paths and toolchain digests,
# and the packaging invariant fails the build over exactly this path shape).
# Generating them keeps the bytes identical run to run -- which is what a
# reproducibility experiment needs -- without committing them.
set -euo pipefail
OUT="${1:?usage: make-fixtures.sh <dir>}"
mkdir -p "$OUT"

cat > "$OUT/wipe.c" <<'FIXTURE_WIPE'
/* The rebuild fixture.
 *
 * interfaces.md §4. Two functions, and the difference between them is the whole
 * point:
 *
 *   wipe_secret  — the TARGET. `buf` is a local that never escapes, so every
 *                  store into it is dead after the last read and a
 *                  store-elimination pass is entitled to delete the memset.
 *                  This is the disappearance the toolchain exists to detect.
 *
 *   control_wipe — the CONTROL, whose effect cannot be optimised away: it zeroes
 *                  a global that is then handed to a function defined in
 *                  another translation unit, so the zeroes are observable and
 *                  the call has to stay. A measurement in which the control's
 *                  count also fell to zero is a broken measurement, not a
 *                  finding.
 *
 * The control matters twice over here. A reproducibility experiment run on a
 * fixture that compiles to nothing reproduces perfectly and proves nothing, so
 * the runner counts call sites in the emitted IR before it compares any bytes,
 * and refuses to report a comparison over an artefact with no effect in it.
 *
 * Counting is by CALL SITE and within one IR unit, never by symbol name: a
 * deleted call leaves `declare void @llvm.memset.p0.i64(...)` behind, and a
 * name search goes on reporting the effect as present until some later pass
 * sweeps the declaration away.
 */

#include <string.h>

/* Defined in main.c, so it is opaque to this translation unit. */
void observe(const unsigned char *p, unsigned long n);

unsigned char control_buffer[4096];

/* CONTROL: the memset survives -O2. */
void control_wipe(void) {
  memset(control_buffer, 0, sizeof control_buffer);
  observe(control_buffer, sizeof control_buffer);
}

/* TARGET: the memset does not survive -O2. */
void wipe_secret(const char *in) {
  char buf[64];
  int i = 0;
  for (; i < (int)sizeof buf - 1 && in[i] != '\0'; ++i) buf[i] = in[i];
  buf[i] = '\0';
  memset(buf, 0, sizeof buf);
}
FIXTURE_WIPE

cat > "$OUT/main.c" <<'FIXTURE_MAIN'
/* Link partner for wipe.c. `observe` lives here so that it is opaque to the
 * translation unit under test: an `observe` defined next to `control_wipe`
 * would be inlined at -O2 and the control's memset would fold away with it,
 * which would make the control useless in exactly the way it exists to prevent.
 *
 * The two macro slots are filled in by the runner. Left empty they expand to
 * nothing and the fixture is deterministic; the reproducibility cases define
 * them to __FILE__ or to __DATE__/__TIME__ in order to make a build that is
 * NOT deterministic and to show which bytes move when it is not.
 */

#include <stdio.h>

#ifndef FIXTURE_STAMP
#define FIXTURE_STAMP "none"
#endif

void wipe_secret(const char *in);
void control_wipe(void);

static unsigned long checksum;

void observe(const unsigned char *p, unsigned long n) {
  unsigned long s = 0;
  for (unsigned long i = 0; i < n; ++i) s += p[i];
  checksum = s;
}

int main(int argc, char **argv) {
  control_wipe();
  wipe_secret(argc > 1 ? argv[1] : "secret");
  printf("stamp=%s checksum=%lu\n", FIXTURE_STAMP, checksum);
  return 0;
}
FIXTURE_MAIN

echo "wrote wipe.c and main.c into $OUT"
