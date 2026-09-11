#!/bin/bash
# The second, independent instrument for WipePin: the IR observer
# (compiler/llvm-pass, IrCheckpoints) watching the erasure fixture with and
# without the repair plugin loaded in the SAME clang invocation.
#
#   run-fixture-loop.sh --lab DIR --observer libIrCheckpoints.so --wipepin libWipePin.so
#
# (or WPIN_LAB / IRCK_PLUGIN / WPIN_PLUGIN in the environment). There are no
# default paths: where the lab and the builds live is the caller's business.
#
# Reads:   the fixtures written by compiler/llvm-pass/tools/make-fixtures.sh,
#          generated into <lab>/fixtures on every run -- never into the repo.
# Writes:  <lab>/records/<cell>.json     the observer's record (via observe.sh)
#          <lab>/wipepin/<cell>.json     WipePin's own record, where loaded
#          <lab>/cells/<cell>.kv         what ran, with both plugins' sha256
#          <lab>/stderr/<cell>.txt       clang's stderr for the cell
#          <lab>/pinsh/<cell>.*          the same WipePin configuration run
#                                        through pin.sh alone, for its exit code
#          <lab>/shapes/                 small sources written here, and the
#                                        pin.sh cells that compile them
#          <lab>/stale/                  compiles that start with a stale record
#                                        at WPIN_OUT
# Decides: nothing. check-fixture-loop.py grades, so the code that produces a
#          number is not the code that says whether it is the right one.
#
# Three groups of cells:
#
#   loop    observer, or observer + WipePin, on the erasure fixture. Every
#           observer+pin cell is also run through pin.sh with the same WPIN_*
#           settings, so the exit code a caller of pin.sh would see is part of
#           the cell (dry-O2 and wrongname-O2 are expected to be 4).
#   pin.sh  pin.sh alone where it must exit 3: no target, and a compile whose
#           pass never runs (-Xclang -disable-llvm-passes).
#   shapes  sources generated into <lab>/shapes/src, each built to show one
#           reading of the record: an initialiser followed by a zeroing loop
#           (followedByUse true and the "partial" line), a trailing memset
#           (followedByUse false, no line), an error-path memset + return inside
#           a loop (false, through clang's cleanup dispatch) and its soundness
#           guard, memset + break with a read after the loop (true), each at
#           -O0/-O1/-O2, non-exact targets (C99 inline, C++ inline), and stale
#           records at WPIN_OUT, which must be gone after a refused compile and
#           after one whose pass never ran.
#
# The observer's -fpass-plugin comes FIRST on the command line and WipePin's
# second. Both register at the pipeline-start extension point, callbacks run in
# load order, so the observer's pre-optimisation checkpoint reads the IR before
# the pin is applied: the "pre" column is the unrepaired program in every cell.
#
# The effect-symbol list is the registered wipe-6 list, read by id from
# compiler/schema/effect-symbol-lists.json -- the list run-matrix.sh configures
# its erasure cells with -- rather than a copy of it, so that this loop and the
# matrix cannot be asking different questions about the same fixture.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COMPILER=$(cd "$HERE/../.." && pwd)

LAB=${WPIN_LAB:-}
OBSERVER=${IRCK_PLUGIN:-}
WIPEPIN=${WPIN_PLUGIN:-}
CC=${WPIN_CC:-clang-18}
PINSH="$HERE/pin.sh"

usage() {
  echo "usage: run-fixture-loop.sh --lab DIR --observer libIrCheckpoints.so --wipepin libWipePin.so" >&2
  exit 3
}

while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB=${2:-}; shift 2 || usage ;;
    --observer) OBSERVER=${2:-}; shift 2 || usage ;;
    --wipepin) WIPEPIN=${2:-}; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$LAB" ] && [ -n "$OBSERVER" ] && [ -n "$WIPEPIN" ] || usage
for so in "$OBSERVER" "$WIPEPIN"; do
  [ -f "$so" ] || { echo "run-fixture-loop.sh: no plugin at $so" >&2; exit 3; }
done
mkdir -p "$LAB"
LAB=$(cd "$LAB" && pwd)

OBSERVE="$COMPILER/llvm-pass/scripts/observe.sh"
REGISTRY="$COMPILER/schema/effect-symbol-lists.json"

WIPE_LIST_ID=wipe-6
EFFECT_SYMBOLS=$(python3 - "$REGISTRY" "$WIPE_LIST_ID" <<'PY'
import json, sys
reg = json.load(open(sys.argv[1], encoding="utf-8"))
print(reg["lists"][sys.argv[2]]["literal"])
PY
)
if [ -z "$EFFECT_SYMBOLS" ]; then
  echo "run-fixture-loop.sh: could not read list $WIPE_LIST_ID from the registry" >&2
  exit 3
fi

IRCK_LAB="$LAB" bash "$COMPILER/llvm-pass/tools/make-fixtures.sh" >/dev/null
FX="$LAB/fixtures/erasure"
[ -f "$FX/target.c" ] || { echo "run-fixture-loop.sh: fixture generation failed" >&2; exit 3; }

rm -rf "$LAB/pinsh" "$LAB/shapes" "$LAB/stale"
mkdir -p "$LAB/wipepin" "$LAB/cells" "$LAB/stderr" "$LAB/pinsh" "$LAB/shapes/src" "$LAB/stale"
OBS_SHA=$(sha256sum "$OBSERVER" | cut -d' ' -f1)
PIN_SHA=$(sha256sum "$WIPEPIN" | cut -d' ' -f1)

failed=0

# pinsh <dir> <id> [VAR=VAL ...] -- <clang args...>
#   pin.sh on its own, with nothing inherited from the caller's WPIN_* and only
#   the settings given here. Prints pin.sh's exit code; pin.sh's own files land
#   at <dir>/<id>.{json,manifest.kv,stderr.txt}, and everything it printed
#   (clang's stderr and its own lines) at <dir>/<id>.console.txt.
pinsh() {
  local dir=$1 id=$2
  shift 2
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN WPIN_CC="$CC" \
      "${envs[@]+"${envs[@]}"}" \
      bash "$PINSH" "$WIPEPIN" "$dir/$id.json" "$@" > /dev/null 2> "$dir/$id.console.txt"
  echo $?
}

# cell <cell-id> <opt> <mode> [VAR=VAL ...]
#   mode  observer        observer only
#         observer+pin    observer, then WipePin, in one invocation
cell() {
  local id=$1 opt=$2 mode=$3
  shift 3
  local rec="$LAB/wipepin/$id.json"
  rm -f "$rec"
  local extra=()
  local pinenv=()
  if [ "$mode" = "observer+pin" ]; then
    extra=(-fpass-plugin="$WIPEPIN")
    pinenv=(WPIN_OUT="$rec" "$@")
  fi
  # env -u: nothing from the caller's environment may configure WipePin in a
  # cell that did not ask for it, and nothing may leak from one cell into the
  # next (the reason run-matrix.sh uses env rather than prefix assignments).
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN \
      IRCK_LAB="$LAB" IRCK_PLUGIN="$OBSERVER" IRCK_CC="$CC" \
      OBS_EXTRACTOR=ir.wipe-effect \
      OBS_PROPERTY_ID=erasure.wipe \
      OBS_TARGET_FN=handle_request \
      OBS_CONTROL_FN=wipe_kept \
      OBS_EFFECT_SYMBOLS="$EFFECT_SYMBOLS" \
      OBS_FIXTURE_REL=erasure/target.c \
      "${pinenv[@]+"${pinenv[@]}"}" \
      bash "$OBSERVE" "$id" "$FX" target.c "$opt" "${extra[@]+"${extra[@]}"}" \
      > /dev/null 2> "$LAB/stderr/$id.txt"
  local rc=$?
  local pinrec=absent
  [ -s "$rec" ] && pinrec=present
  # The same WipePin settings through pin.sh, WipePin alone: the exit code a
  # caller of pin.sh gets for this configuration.
  local pinshrc=not-run
  if [ "$mode" = "observer+pin" ]; then
    pinshrc=$(pinsh "$LAB/pinsh" "$id" "$@" -- "$opt" -c "$FX/target.c" -o "$LAB/pinsh/$id.o")
  fi
  {
    echo "cellId=$id"
    echo "opt=$opt"
    echo "mode=$mode"
    echo "observeRc=$rc"
    echo "observerSha256=$OBS_SHA"
    if [ "$mode" = "observer+pin" ]; then
      echo "wipepinSha256=$PIN_SHA"
      echo "wipepinRecord=$pinrec"
      echo "wipepinEnv=$*"
    else
      echo "wipepinSha256=not-loaded"
      echo "wipepinRecord=not-loaded"
      echo "wipepinEnv="
    fi
    echo "effectSymbolList=$WIPE_LIST_ID"
    echo "pinShRc=$pinshrc"
  } > "$LAB/cells/$id.kv"
  if [ $rc -ne 0 ] || { [ "$mode" = "observer+pin" ] && [ "$pinrec" != present ]; }; then
    echo "run-fixture-loop.sh: $id: observe rc=$rc, WipePin record $pinrec" >&2
    failed=1
  fi
  echo "$id"
}

for O in -O0 -O1 -O2 -O3; do
  cell "base$O" "$O" observer
  cell "pin$O" "$O" observer+pin WPIN_TARGET_FNS=handle_request
done

# The red control: the plugin loaded and configured exactly as above, but told
# to change nothing. If the loss does not come back here, whatever made the
# pin cells PRESENT was not the volatile flag.
cell "dry-O2" -O2 observer+pin WPIN_TARGET_FNS=handle_request WPIN_DRY_RUN=1

# The misspelt name. The plugin loads, writes a well-formed record, pins
# nothing, and the loss must come back -- with the misspelling on record.
cell "wrongname-O2" -O2 observer+pin WPIN_TARGET_FNS=handle_requestX

# ------------------------------------------------------------ pin.sh alone
# kv <file> <key=value ...>
kv() { local f=$1; shift; printf '%s\n' "$@" > "$f"; }

rc=$(pinsh "$LAB/pinsh" notarget-O2 -- -O2 -c "$FX/target.c" -o "$LAB/pinsh/notarget-O2.o")
kv "$LAB/pinsh/notarget-O2.kv" "cellId=notarget-O2" "pinShRc=$rc" "wipepinSha256=$PIN_SHA"
echo notarget-O2
rc=$(pinsh "$LAB/pinsh" nollvmpasses-O2 WPIN_TARGET_FNS=handle_request -- \
       -O2 -Xclang -disable-llvm-passes -c "$FX/target.c" -o "$LAB/pinsh/nollvmpasses-O2.o")
kv "$LAB/pinsh/nollvmpasses-O2.kv" "cellId=nollvmpasses-O2" "pinShRc=$rc" "wipepinSha256=$PIN_SHA"
echo nollvmpasses-O2

# ------------------------------------------------------------ shapes
# Each source is one function `handle` (or a named inline target) holding one
# 32-byte stack buffer that an opaque external function fills and another
# reads. Written here on every run, never into the repository.
SRC="$LAB/shapes/src"

# The initialiser is the only zero-fill memset; the wipe is a loop of stores,
# which at pipeline start is still a loop. The pin lands on the initialiser.
cat > "$SRC/initloop.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32] = {0};
  derive(key);
  use(key, 32);
  for (int i = 0; i < 32; i++) key[i] = 0;
  return 0;
}
SHAPE_EOF

# The initialiser again, and the wipe in a helper the target calls. The target
# does not read "nothing to pin": the initialiser is pinnable.
cat > "$SRC/inithelper.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
static void scrub(unsigned char *p, unsigned long n) { memset(p, 0, n); }
int handle(void) {
  unsigned char key[32] = {0};
  derive(key);
  use(key, 32);
  scrub(key, sizeof key);
  return 0;
}
SHAPE_EOF

# A clear-before-fill memset and a trailing wipe memset on the same buffer:
# two sites, the first followed by a use, the second not.
cat > "$SRC/initwipe.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  memset(key, 0, sizeof key);
  derive(key);
  use(key, 32);
  memset(key, 0, sizeof key);
  return 0;
}
SHAPE_EOF

# The clear-before-fill memset again, but every later use goes through a copy
# of the address held in another local: the one step through memory that
# followedByUse follows.
cat > "$SRC/aliasinit.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  unsigned char *p = key;
  memset(key, 0, sizeof key);
  derive(p);
  use(p, 32);
  for (int i = 0; i < 32; i++) p[i] = 0;
  return 0;
}
SHAPE_EOF

# The wipe the plugin exists for: a trailing memset, the buffer's last use.
cat > "$SRC/trailing.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  memset(key, 0, sizeof key);
  return 0;
}
SHAPE_EOF

# The error-path wipe inside a loop (the fable_N_token_r3.c shape): a memset
# and a `return` inside the loop body, while the body also reads the buffer, and
# a trailing memset after the loop. At -O1 and above the body's local `n` has a
# cleanup, so the `return` goes through clang's cleanup dispatch, whose switch
# has an edge back to the loop header; no execution takes it from the return
# path. wipe-pin-v1 read that edge as a later use; wipe-pin-v2 must not.
cat > "$SRC/loopreturn.c" <<'SHAPE_EOF'
#include <string.h>
#include <unistd.h>
void derive(unsigned char *k);
int handle(int fd) {
  unsigned char key[32];
  unsigned long total = 0;
  derive(key);
  while (total < sizeof key) {
    long n = write(fd, key + total, sizeof key - total);
    if (n < 0) {
      memset(key, 0, sizeof key);
      return -1;
    }
    total += (unsigned long)n;
  }
  memset(key, 0, sizeof key);
  return 0;
}
SHAPE_EOF

# The soundness guard for that refinement: the same loop, but the memset is
# followed by `break`, and the buffer IS read after the loop. The break goes
# through the same cleanup dispatch, and the edge its stored constant selects
# leads to the read. followedByUse must stay true: a refinement that took the
# wrong edge, or pruned an edge it could not prove infeasible, would hide it.
cat > "$SRC/loopbreakuse.c" <<'SHAPE_EOF'
#include <string.h>
#include <unistd.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(int fd) {
  unsigned char key[32];
  unsigned long total = 0;
  derive(key);
  while (total < sizeof key) {
    long n = write(fd, key + total, sizeof key - total);
    if (n < 0) {
      memset(key, 0, sizeof key);
      break;
    }
    total += (unsigned long)n;
  }
  use(key, 32);
  return 0;
}
SHAPE_EOF

# A C99 inline definition (no extern declaration in this unit): emitted, when
# optimising, as available_externally.
cat > "$SRC/c99inline.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
inline void wipe_inline(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  memset(key, 0, sizeof key);
}
void call_inline(void) { wipe_inline(); }
SHAPE_EOF

# A C++ inline function, with C language linkage so its IR name is its source
# name: linkonce_odr.
cat > "$SRC/cxxinline.cpp" <<'SHAPE_EOF'
#include <cstring>
extern "C" void derive(unsigned char *k);
extern "C" void use(const unsigned char *k, unsigned n);
extern "C" inline void wipe_cxx(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  std::memset(key, 0, sizeof key);
}
extern "C" void call_cxx(void) { wipe_cxx(); }
SHAPE_EOF

# shape <id> <source> <target> [opt]: -g at <opt> (default -O2), textual IR out,
# pin.sh's exit code kept.
shape() {
  local id=$1 src=$2 target=$3 opt=${4:--O2}
  local rc
  rc=$(pinsh "$LAB/shapes" "$id" WPIN_TARGET_FNS="$target" -- \
         "$opt" -g -S -emit-llvm "$SRC/$src" -o "$LAB/shapes/$id.ll")
  kv "$LAB/shapes/$id.kv" "cellId=$id" "source=$src" "target=$target" "opt=$opt" \
     "pinShRc=$rc" "wipepinSha256=$PIN_SHA"
  echo "$id"
}
shape initloop   initloop.c    handle
shape inithelper inithelper.c  handle
shape initwipe   initwipe.c    handle
shape aliasinit  aliasinit.c   handle
shape trailing   trailing.c    handle
shape c99inline  c99inline.c   wipe_inline
shape cxxinline  cxxinline.cpp wipe_cxx
# The two loop shapes at -O2 like the rest, and also at -O0, where there is no
# cleanup dispatch, and -O1, the first level that has it.
shape loopreturn       loopreturn.c   handle
shape loopreturn-O0    loopreturn.c   handle -O0
shape loopreturn-O1    loopreturn.c   handle -O1
shape loopbreakuse     loopbreakuse.c handle
shape loopbreakuse-O0  loopbreakuse.c handle -O0
shape loopbreakuse-O1  loopbreakuse.c handle -O1

# ------------------------------------------------------------ stale records
# clang directly, not pin.sh: pin.sh deletes its record path itself, which would
# make these cells prove nothing about the plugin. Each starts with a file that
# is not a record from this compile sitting at WPIN_OUT.
#
# stale <id> <what-is-at-WPIN_OUT: file|dir> [VAR=VAL ...] -- <clang args...>
stale() {
  local id=$1 what=$2
  shift 2
  local out="$LAB/stale/$id.json"
  rm -rf "$out"
  if [ "$what" = dir ]; then
    mkdir -p "$out" && echo "not a record" > "$out/keep.txt"
  else
    echo "stale: not a record from this compile" > "$out"
  fi
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN \
      WPIN_OUT="$out" "${envs[@]+"${envs[@]}"}" \
      "$CC" -fpass-plugin="$WIPEPIN" "$@" > /dev/null 2> "$LAB/stale/$id.stderr.txt"
  local rc=$?
  local state=absent
  [ -d "$out" ] && state=dir
  [ -f "$out" ] && state=file
  kv "$LAB/stale/$id.kv" "cellId=$id" "before=$what" "rc=$rc" "after=$state" \
     "wipepinSha256=$PIN_SHA"
  echo "$id"
}
stale stale-refused  file -- -O2 -c "$SRC/trailing.c" -o "$LAB/stale/stale-refused.o"
stale stale-nopasses file WPIN_TARGET_FNS=handle -- \
      -O2 -Xclang -disable-llvm-passes -c "$SRC/trailing.c" -o "$LAB/stale/stale-nopasses.o"
stale stale-live     file WPIN_TARGET_FNS=handle -- -O2 -c "$SRC/trailing.c" -o "$LAB/stale/stale-live.o"
stale stale-dir      dir  WPIN_TARGET_FNS=handle -- -O2 -c "$SRC/trailing.c" -o "$LAB/stale/stale-dir.o"

if [ $failed -ne 0 ]; then
  echo "run-fixture-loop.sh: at least one cell did not produce its records" >&2
  exit 3
fi
exit 0
