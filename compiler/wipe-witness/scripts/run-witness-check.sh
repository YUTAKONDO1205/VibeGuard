#!/bin/bash
# The witness, run on a handful of generated sources with a real compiler and
# a real repair plugin, and graded against a fixed table of expected exit codes.
#
#   bash compiler/wipe-witness/scripts/run-witness-check.sh --lab <dir> \
#        --wipepin <libWipePin.so> --witness <libWipeWitness.so> [--cc clang-18] \
#        [--wipepin-gcc <libWipePinGcc.so> --witness-gcc <libWipeWitnessGcc.so> [--gcc gcc-13]]
#
# The GCC cells run only when both GCC plugins are given.
#
# Everything is generated into <dir>; nothing is written under compiler/. The
# sources are written here rather than kept as files in the tree, because the
# repository's own scanner reads every C file under compiler/.
#
# For every cell it checks three things:
#   - the witness changes nothing: the -S with the repair plugin and the
#     witness loaded is byte-identical with the -S with the repair plugin alone
#     (and, for the witness alone, with the stock -S);
#   - scripts/witness_check.py exits with the cell's expected code;
#   - every compile exits 0.
#
# Expected codes, written from what each cell is for before it first ran
# (clang 18.1.3, gcc 13.3.0; the expectations are about the rule, not the
# version):
#   musttail-O2    0  a loop wipe before a musttail call, WPIN_BUFFER_BARRIER=1:
#                     the barrier goes before the call and is still there
#   musttail-O0    0  the same at -O0
#   memset-O2      0  a memset wipe, switches off: the pinned memset is kept
#   inline-O2      0  the wipe helper is inlined away (not judged); its caller
#                     has the volatile memset
#   deadwipe-O2    2  a pinned memset in a branch on a static flag nothing
#                     sets: the optimiser proves the branch dead and deletes it
#                     with the pin, while the function stays. SILENT, and
#                     correctly so by the rule: the rule cannot tell a repair
#                     deleted as dead code from one deleted by mistake
#   deadwipe-O0    0  the same at -O0, where nothing is deleted
#   exit-O2        4  a wipe only on the path to exit(): WipePin places no
#                     barrier there (it cannot cover that path), so there is
#                     nothing to judge
#   dry-O2         4  WPIN_DRY_RUN=1: nothing placed
#   reversed-O2    3  the witness loaded before WipePin: refused
#   nopin-O2       3  the witness alone, no WipePin record: refused
# and with GCC:
#   gcc-memset-O2   0  as memset-O2; the pin is WipePinGcc's barrier
#   gcc-loop-O2     0  a loop wipe, WPIN_BUFFER_BARRIER=1
#   gcc-inline-O2   0  as inline-O2
#   gcc-deadwipe-O2 2  as deadwipe-O2
#   gcc-deadwipe-O0 0  as deadwipe-O0
#   gcc-dry-O2      4  as dry-O2
#   gcc-reversed-O2 0  the witness first on the command line: GCC's witness
#                      places its start pass after a pass that follows
#                      WipePinGcc's, so the order does not depend on the
#                      command line and nothing is refused
#   gcc-nopin-O2    3  as nopin-O2
#
# Exit codes: 0 every expectation held, 2 at least one did not, 3 a tool or a
# record this script needs was missing.
set -u

LAB= WIPEPIN= WITNESS= CC=clang-18 WIPEPIN_GCC= WITNESS_GCC= GCC=gcc-13
while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB=$2; shift 2 ;;
    --wipepin) WIPEPIN=$2; shift 2 ;;
    --witness) WITNESS=$2; shift 2 ;;
    --cc) CC=$2; shift 2 ;;
    --wipepin-gcc) WIPEPIN_GCC=$2; shift 2 ;;
    --witness-gcc) WITNESS_GCC=$2; shift 2 ;;
    --gcc) GCC=$2; shift 2 ;;
    *) echo "run-witness-check.sh: unknown argument $1" >&2; exit 3 ;;
  esac
done
[ -n "$LAB" ] && [ -n "$WIPEPIN" ] && [ -n "$WITNESS" ] || {
  echo "usage: run-witness-check.sh --lab <dir> --wipepin <libWipePin.so> --witness <libWipeWitness.so> [--cc clang-18] [--wipepin-gcc <so> --witness-gcc <so> [--gcc gcc-13]]" >&2
  exit 3
}
if [ -n "$WIPEPIN_GCC$WITNESS_GCC" ] && { [ -z "$WIPEPIN_GCC" ] || [ -z "$WITNESS_GCC" ]; }; then
  echo "run-witness-check.sh: give both --wipepin-gcc and --witness-gcc, or neither" >&2
  exit 3
fi
for f in "$WIPEPIN" "$WITNESS" ${WIPEPIN_GCC:+"$WIPEPIN_GCC"} ${WITNESS_GCC:+"$WITNESS_GCC"}; do
  [ -s "$f" ] || { echo "run-witness-check.sh: no plugin at $f" >&2; exit 3; }
done
command -v "$CC" > /dev/null || { echo "run-witness-check.sh: $CC not found" >&2; exit 3; }
if [ -n "$WIPEPIN_GCC" ]; then
  command -v "$GCC" > /dev/null || { echo "run-witness-check.sh: $GCC not found" >&2; exit 3; }
fi
command -v python3 > /dev/null || { echo "run-witness-check.sh: python3 not found" >&2; exit 3; }
HERE=$(cd "$(dirname "$0")" && pwd)
CHECK="$HERE/witness_check.py"

rm -rf "$LAB"
mkdir -p "$LAB/src" || exit 3
S="$LAB/src"
HDR='void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);'

cat > "$S/musttail.c" <<EOF
$HDR
int next(int x);
int handle(int x) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  __attribute__((musttail)) return next(x);
}
EOF
cat > "$S/loop.c" <<EOF
$HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
}
EOF
cat > "$S/memset.c" <<EOF
#include <string.h>
$HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  memset(key, 0, sizeof key);
}
EOF
cat > "$S/inline.c" <<EOF
#include <string.h>
$HDR
static void wipe(void *p, unsigned long n) { memset(p, 0, n); }
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  wipe(key, sizeof key);
}
EOF
cat > "$S/deadwipe.c" <<EOF
#include <string.h>
$HDR
static int wipe_enabled;
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  if (wipe_enabled) memset(key, 0, sizeof key);
}
EOF
cat > "$S/exit.c" <<EOF
$HDR
void exit(int);
int handle(int bad, int s) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  if (bad) {
    for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
    exit(s);
  }
  return 0;
}
EOF

CLEAN=(env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS
       -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER -u WWIT_OUT)
failed=0
missing=0
note() { echo "run-witness-check.sh: $*"; }

# cell <vendor: clang|gcc> <id> <expected exit> <order: pw|wp|w> <source> <level> [VAR=VAL ...]
#   pw  the repair plugin, then the witness (the supported order)
#   wp  the witness, then the repair plugin
#   w   the witness alone
cell() {
  local vendor=$1 id=$2 want=$3 ord=$4 src=$5 lvl=$6
  shift 6
  local d="$LAB/$id" plug=() ref=() rc ok=1 cc flag pin wit
  if [ "$vendor" = gcc ]; then
    cc=$GCC flag=-fplugin pin=$WIPEPIN_GCC wit=$WITNESS_GCC
  else
    cc=$CC flag=-fpass-plugin pin=$WIPEPIN wit=$WITNESS
  fi
  mkdir -p "$d"
  case $ord in
    pw) plug=("$flag=$pin" "$flag=$wit") ;;
    wp) plug=("$flag=$wit" "$flag=$pin") ;;
    w)  plug=("$flag=$wit") ;;
  esac
  # The reference: the same compile without the witness.
  if [ "$ord" = w ]; then ref=(); else ref=("$flag=$pin"); fi
  (cd "$S" && "${CLEAN[@]}" WPIN_OUT="$d/ref.json" "$@" \
     "$cc" "$lvl" "${ref[@]}" -S "$src" -o "$d/ref.s" 2> "$d/ref.err")
  rc=$?
  [ $rc -eq 0 ] || { note "$id: the reference compile exited $rc"; ok=0; }
  (cd "$S" && "${CLEAN[@]}" WPIN_OUT="$d/pin.json" WWIT_OUT="$d/witness.json" "$@" \
     "$cc" "$lvl" "${plug[@]}" -S "$src" -o "$d/with.s" 2> "$d/with.err")
  rc=$?
  [ $rc -eq 0 ] || { note "$id: the compile with the witness exited $rc"; ok=0; }
  if ! cmp -s "$d/ref.s" "$d/with.s"; then
    note "$id: the -S with the witness differs from the -S without it"
    ok=0
  fi
  if [ ! -s "$d/witness.json" ]; then
    note "$id: no witness record"
    missing=1
    ok=0
  fi
  python3 -B "$CHECK" --pin "$d/pin.json" --witness "$d/witness.json" > "$d/check.txt" 2>&1
  rc=$?
  sed "s/^/  $id: /" "$d/check.txt"
  if [ "$rc" != "$want" ]; then
    note "$id: witness_check.py exited $rc, expected $want"
    ok=0
  fi
  if [ $ok -eq 1 ]; then note "$id: ok (exit $rc)"; else failed=1; fi
}

# wants_line <id> <text>: the cell's checker output must contain the text.
wants_line() {
  grep -qF "$2" "$LAB/$1/check.txt" || { note "$1: no line containing '$2'"; failed=1; }
}

BB=(WPIN_TARGET_FNS=handle WPIN_BUFFER_BARRIER=1)
cell clang musttail-O2 0 pw musttail.c -O2 "${BB[@]}"
cell clang musttail-O0 0 pw musttail.c -O0 "${BB[@]}"
cell clang memset-O2   0 pw memset.c   -O2 WPIN_TARGET_FNS=handle
cell clang inline-O2   0 pw inline.c   -O2 WPIN_TARGET_FNS=handle,wipe
cell clang deadwipe-O2 2 pw deadwipe.c -O2 WPIN_TARGET_FNS=handle
cell clang deadwipe-O0 0 pw deadwipe.c -O0 WPIN_TARGET_FNS=handle
cell clang exit-O2     4 pw exit.c     -O2 "${BB[@]}"
cell clang dry-O2      4 pw memset.c   -O2 WPIN_TARGET_FNS=handle WPIN_DRY_RUN=1
cell clang reversed-O2 3 wp musttail.c -O2 "${BB[@]}"
cell clang nopin-O2    3 w  memset.c   -O2
wants_line inline-O2 'wipe: placed 1; at the end: absent: not judged'
wants_line deadwipe-O2 'handle: placed 1; at the end: defined, barriers 0, volatile zero memsets 0: SILENT'
wants_line reversed-O2 "order 'witness-first'"

if [ -n "$WIPEPIN_GCC" ]; then
  cell gcc gcc-memset-O2   0 pw memset.c   -O2 WPIN_TARGET_FNS=handle
  cell gcc gcc-loop-O2     0 pw loop.c     -O2 "${BB[@]}"
  cell gcc gcc-inline-O2   0 pw inline.c   -O2 WPIN_TARGET_FNS=handle,wipe
  cell gcc gcc-deadwipe-O2 2 pw deadwipe.c -O2 WPIN_TARGET_FNS=handle
  cell gcc gcc-deadwipe-O0 0 pw deadwipe.c -O0 WPIN_TARGET_FNS=handle
  cell gcc gcc-dry-O2      4 pw memset.c   -O2 WPIN_TARGET_FNS=handle WPIN_DRY_RUN=1
  cell gcc gcc-reversed-O2 0 wp loop.c     -O2 "${BB[@]}"
  cell gcc gcc-nopin-O2    3 w  memset.c   -O2
  wants_line gcc-inline-O2 'wipe: placed 1; at the end: absent: not judged'
  wants_line gcc-deadwipe-O2 'handle: placed 1; at the end: defined, barriers 0, volatile zero memsets 0: SILENT'
fi

if [ $missing -ne 0 ]; then
  note "at least one witness record was missing"
  exit 3
fi
[ $failed -eq 0 ] || { note "at least one expectation did not hold"; exit 2; }
note "every expectation held"
exit 0
