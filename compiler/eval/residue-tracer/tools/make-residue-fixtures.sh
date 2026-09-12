#!/bin/bash
# Write this lane's measurement inputs into the lab, on the side that produces them.
#
#   bash compiler/eval/residue-tracer/tools/make-residue-fixtures.sh
#   RESIDUE_LAB=/somewhere bash compiler/eval/residue-tracer/tools/make-residue-fixtures.sh
#
# Generated rather than committed, for the reason llvm-pass/tools/make-fixtures.sh
# gives: scripts/check-packaging-invariants.mjs refuses any tracked path under
# compiler/ with a `fixtures` segment, because a measurement input in the
# published tree carries absolute paths and per-machine toolchain digests. This
# script IS the fixture and is reviewable as one.
#
# THE TRACER NEVER APPEARS HERE. Every buffer below is filled from a file
# descriptor the runner opens at run time. A literal would be constant-folded,
# would appear in .rodata, and would then be found by the observer in a place no
# wipe was ever responsible for. The runner generates 32 random bytes per run and
# the only path the bytes take into the process is read(2).
#
# EVERY target.c CARRIES A CO-RESIDENT CONTROL. `keep[32]` is filled from the
# same descriptor, passed to the same consumer, and never wiped, in the same
# frame as `secret[32]`. It is what makes a NONE reading mean anything: a cell
# whose control needle is not fully readable did not measure the subject, it
# measured a broken instrument. That is invariant 2 applied per measurement
# rather than per run.
set -eu

LAB=${RESIDUE_LAB:-$HOME/vg-lab/residue-tracer}
FX="$LAB/fixtures"
mkdir -p "$FX"

# ---------------------------------------------------------------- main.c ----
#
# argv[1] is the path to the file holding the tracer bytes. main opens it and
# hands over the DESCRIPTOR, never a caller-side buffer: a buffer filled here
# would live in main's frame, which is ABOVE the window the observer reads, and
# would make the residue reading depend on a frame the subject does not own.
#
# The return value of handle_request is used, so the call cannot be compiled into
# a tail jump and the return address the observer breaks on stays inside main.
cat > "$FX/main.c" <<'FIXTURE_EOF'
#include <fcntl.h>
#include <unistd.h>

int handle_request(int fd);

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 3;
    int r = handle_request(fd);
    close(fd);
    return r == 0 ? 0 : 1;
}
FIXTURE_EOF

# -------------------------------------------------------------- opaque.c ----
#
# COMPILED AT -O0 ALWAYS, and that is a measurement decision rather than a
# convenience. At -O2 the consumer loop vectorises: sixteen bytes of the tracer
# land in an xmm register, the observer reads register residue, and the reading
# is attributed to a wipe that never touched that register. -O0 keeps the
# consumer a byte-at-a-time loop, so the largest fragment it can leave in a
# register is one byte -- below any threshold this lane grades on.
#
# get_secret reads straight into the CALLER's buffer. An intermediate buffer here
# would live in this frame, which is DEEPER than handle_request's and therefore
# inside the window; its residue would be read as the subject's.
cat > "$FX/opaque.c" <<'FIXTURE_EOF'
#include <unistd.h>

volatile unsigned char sink;

int get_secret(int fd, unsigned char *out, unsigned long n) {
    unsigned long got = 0;
    while (got < n) {
        long k = read(fd, out + got, n - got);
        if (k <= 0) return -1;
        got += (unsigned long)k;
    }
    return 0;
}

void consume(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}

/* The two externals the find step's own positive control calls. CONTROL from
 * ai-generated/lib/ablation-cell.mjs is appended to every target.c before
 * compilation -- that is how this lane reaches the same verdict code the corpus
 * measurement uses -- and vgctl_control is a global, so the link needs these. */
void vgctl_fill(unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) p[i] = (unsigned char)(i * 7u + 1u);
}

void vgctl_use(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}
FIXTURE_EOF

# ------------------------------------------------------------- target.c -----
#
# Four variants, one file each, differing only in the wipe. `retain` is not an
# idiom: it is the control that shows the window and the reader work at all.
#
# Byte layout of the tracer file, which the runner writes and these read in
# order: [0,32) is the subject tracer, [32,64) the co-resident control tracer.

emit_target() {
    local name="$1" wipe="$2" extra_include="$3"
    cat > "$FX/target-$name.c" <<FIXTURE_EOF
/* Residue subject: one secret, one co-resident control, one wipe idiom.
 *
 * handle_request OWNS the buffer, and its return is the stop point. "Just after
 * the wipe" is unrealisable above -O0 -- the wipe is inlined and there is no
 * wipe-function return -- so the observable instant is the one where the frame
 * holding the buffer is dead and the caller has executed nothing.
 *
 * keep[] is the co-resident control. It is filled from the same descriptor and
 * consumed by the same external function, and nothing wipes it. If the observer
 * cannot read keep[] at the stop, it did not measure secret[] either. */
$extra_include
int get_secret(int fd, unsigned char *out, unsigned long n);
void consume(const unsigned char *p, unsigned long n);

int handle_request(int fd) {
    unsigned char secret[32];
    unsigned char keep[32];
    if (get_secret(fd, secret, sizeof secret) != 0) return -1;
    if (get_secret(fd, keep, sizeof keep) != 0) return -1;
    consume(secret, sizeof secret);
    consume(keep, sizeof keep);
$wipe
    return 0;
}
FIXTURE_EOF
}

emit_target retain "" ""

emit_target memset \
"    memset(secret, 0, sizeof secret);" \
"#include <string.h>"

# The dominant real-world shape puts `volatile` on a DECLARATION that precedes
# the loop, so the loop text never mentions it. wipeSpans() in
# ai-generated/lib/ablation-cell.mjs finds declaration and loop as a pair and
# ablates both; writing it any other way would measure a different thing than the
# corpus measurement does.
emit_target volatile-loop \
"    {
        volatile unsigned char *p = secret;
        for (unsigned long i = 0; i < sizeof secret; i++) p[i] = 0;
    }" \
""

emit_target explicit-bzero \
"    explicit_bzero(secret, sizeof secret);" \
"#include <string.h>"

ls -1 "$FX"
