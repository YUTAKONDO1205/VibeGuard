#!/bin/bash
# The second, independent instrument for WipePin: the IR observer
# (compiler/llvm-pass, IrCheckpoints) watching the erasure fixture with and
# without the repair plugin loaded in the SAME clang invocation.
#
#   run-fixture-loop.sh --lab DIR --observer libIrCheckpoints.so --wipepin libWipePin.so \
#                       [--baseline libWipePin-v2.so]
#
# (or WPIN_LAB / IRCK_PLUGIN / WPIN_PLUGIN / WPIN_BASELINE_PLUGIN in the
# environment). There are no default paths: where the lab and the builds live
# is the caller's business. --baseline is a WipePin built from 22e7222, the last
# wipe-pin-v2 writer; with it, the v3 cells also compare this build's -S output
# with the switches off against that build's, and without it they say they did
# not.
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
#          <lab>/lto/                    -flto compiles with WipePin, and links
#                                        with WipePin on the link line
#          <lab>/xtu/                    four units generated into xtu/src,
#                                        each cell's objects, stderr, record and
#                                        linked executable in xtu/<cell>/
#          <lab>/v3/                     sources generated into v3/src, each
#                                        case's -S output, record, pin.sh files
#                                        and linked executable per arm
# Decides: nothing. check-fixture-loop.py grades, so the code that produces a
#          number is not the code that says whether it is the right one.
#
# Six groups of cells:
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
#   lto     the trailing shape compiled -O2 -flto with WipePin (its record must
#           be written, and no link-time line printed), and, for full and thin
#           LTO, the same compile followed by a link that loads WipePin on the
#           link line with the SAME WPIN_OUT -- a build that exports WPIN_* to
#           every step. The link never runs pipeline start, so WipePin cannot
#           run there; what it must do is say so, once, and that the compile's
#           record was removed when it loaded. Each such link is paired with a
#           stock link of the same bitcode, whose output it must equal. Also:
#           the thin form compiled and linked at -O0 (a ThinLTO link at -O0
#           invokes no extension point at all, which is why WipePin speaks from
#           a pass-instrumentation callback); a full-LTO link started with
#           nothing at WPIN_OUT (the compile's record moved aside first), whose
#           line must say there was no file; and a compile, not a link, under
#           -Xclang -disable-llvm-passes -S -emit-llvm, which builds no
#           pipeline but still runs the IR printer as a pass.
#   xtu     a wipe helper in another translation unit: secure_wipe(p, n) in
#           wipe.c, called on a local buffer's last use by handle() in use.c,
#           with main.c and io.c (the producer and consumer, never compiled
#           -flto), linked into an executable at -O2 -- stock without LTO, and
#           for full and thin LTO a stock build, a build with WipePin at the
#           compile of wipe.c only, and the same as a dry run. The loss here is
#           one only the LTO link can create, by inlining the helper; the
#           checker reads the executable itself.
#   v3      what wipe-pin-v3 adds. For each call-shaped wipe a switch repairs --
#           memset under -D_FORTIFY_SOURCE=2 and =3 (memset.inline), bzero under
#           both (bzero.inline), __memset_chk, a libcall memset (-fno-builtin),
#           a copy from an all-zero constant global without FORTIFY (llvm.memcpy)
#           and under =2 (memcpy.inline) -- four arms, each linked with the
#           same io.c and main.c into an executable the checker disassembles:
#           stock (no plugin), off (WipePin, switches unset), ext (the switch
#           set) and dry (the switch set, WPIN_DRY_RUN=1), and with --baseline
#           a fifth, orig (the v2 build, same target). The same four arms for
#           the buffer barrier: a wipe written as a loop of zero stores
#           (WPIN_BUFFER_BARRIER), without and with -g, and the same loop
#           through an advancing pointer; and, through pin.sh alone, the
#           buffer barrier where it must not go or must not cover: a buffer
#           whose only zero fill is an `= {0}` initialiser, or an initialiser
#           loop; a variable-length array in a branch (-O0, -O2); a musttail
#           call after the wipe (-O0, -O2, -Os, and a variable-length array at
#           -O2); a lifetime end on one path and a musttail call on another
#           (-O2); a wipe only on a path that ends in exit() (-O2); a wipe
#           loop bounded by a pointer comparison (-O2); a
#           buffer declared in a loop body and wiped each iteration; and
#           __builtin_memcpy_inline from a zero constant built -ffreestanding
#           (WPIN_ZERO_COPY). Those are compiled -S and -S -emit-llvm, and the
#           IR is read by opt-<N> -passes=verify (WPIN_OPT names another opt).
#           Then pin.sh refusing switch values other than 0 and 1, and the
#           version handshake: the trailing shape's front-end IR read back with
#           -x ir as clang wrote it, with its llvm.ident rewritten to the next
#           major version (clang 19.1.1 for clang-18), and with no llvm.ident,
#           each -S through pin.sh and stock.
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
BASELINE=${WPIN_BASELINE_PLUGIN:-}
CC=${WPIN_CC:-clang-18}
PINSH="$HERE/pin.sh"

usage() {
  echo "usage: run-fixture-loop.sh --lab DIR --observer libIrCheckpoints.so --wipepin libWipePin.so [--baseline libWipePin-v2.so]" >&2
  exit 3
}

while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB=${2:-}; shift 2 || usage ;;
    --observer) OBSERVER=${2:-}; shift 2 || usage ;;
    --wipepin) WIPEPIN=${2:-}; shift 2 || usage ;;
    --baseline) BASELINE=${2:-}; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$LAB" ] && [ -n "$OBSERVER" ] && [ -n "$WIPEPIN" ] || usage
for so in "$OBSERVER" "$WIPEPIN" ${BASELINE:+"$BASELINE"}; do
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

rm -rf "$LAB/pinsh" "$LAB/shapes" "$LAB/stale" "$LAB/lto" "$LAB/xtu" "$LAB/v3"
mkdir -p "$LAB/wipepin" "$LAB/cells" "$LAB/stderr" "$LAB/pinsh" "$LAB/shapes/src" "$LAB/stale" "$LAB/lto" \
         "$LAB/xtu/src" "$LAB/v3/src"
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
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER WPIN_CC="$CC" \
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
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER \
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
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER \
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

# ------------------------------------------------------------ LTO
# lto <id> <full|thin|none> <compile|linkline|linkline-nofile|nopasses-ir> <opt>
#   compile          trailing.c at <opt> -flto[=thin] with WipePin, record at
#                    <lab>/lto/<id>.json, object <id>.o, stderr
#                    <id>.compile.stderr.txt
#   linkline         the same compile; a copy of whatever it left at WPIN_OUT is
#                    kept as <id>.compile.json; then a stock link of the object
#                    at <opt> (<id>.stock.so) and a link of the same object at
#                    <opt> with WipePin on the link line and the same WPIN_OUT /
#                    WPIN_TARGET_FNS in its environment (<id>.plugin.so, stderr
#                    <id>.link.stderr.txt)
#   linkline-nofile  as linkline, but the compile's record is moved to
#                    <id>.compile.json, so nothing is at WPIN_OUT when the link
#                    loads the plugin
#   nopasses-ir      form none: trailing.c at <opt> -Xclang -disable-llvm-passes
#                    -S -emit-llvm with WipePin (<id>.ll), nothing at WPIN_OUT
#                    beforehand; no link
# Written down, not judged: rc's and what is at WPIN_OUT before and after each
# step.
LTOD="$LAB/lto"
lto() {
  local id=$1 form=$2 what=$3 opt=$4
  local cflag=
  local lflags=()
  case "$form" in
    full) cflag=-flto; lflags=(-flto) ;;
    thin) cflag=-flto=thin; lflags=(-flto=thin -Wl,--thinlto-jobs=1) ;;
    none) ;;
    *) echo "run-fixture-loop.sh: lto: unknown form $form" >&2; exit 3 ;;
  esac
  local out="$LTOD/$id.json" obj="$LTOD/$id.o"
  rm -rf "$out"
  local cstate_before=absent
  if [ "$what" = nopasses-ir ]; then
    obj="$LTOD/$id.ll"
    env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER \
        WPIN_OUT="$out" WPIN_TARGET_FNS=handle \
        "$CC" "$opt" -Xclang -disable-llvm-passes -fpass-plugin="$WIPEPIN" \
        -S -emit-llvm "$SRC/trailing.c" -o "$obj" \
        > /dev/null 2> "$LTOD/$id.compile.stderr.txt"
  else
    env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER \
        WPIN_OUT="$out" WPIN_TARGET_FNS=handle \
        "$CC" "$opt" "$cflag" -fpass-plugin="$WIPEPIN" -c "$SRC/trailing.c" -o "$obj" \
        > /dev/null 2> "$LTOD/$id.compile.stderr.txt"
  fi
  local crc=$?
  local cstate=absent
  [ -d "$out" ] && cstate=dir
  [ -f "$out" ] && cstate=file
  local src_rc=not-run lrc=not-run lstate=not-run bstate=not-run
  case "$what" in
    linkline|linkline-nofile)
      if [ "$what" = linkline-nofile ]; then
        [ -f "$out" ] && mv "$out" "$LTOD/$id.compile.json"
      else
        [ -f "$out" ] && cp "$out" "$LTOD/$id.compile.json"
      fi
      bstate=absent
      [ -d "$out" ] && bstate=dir
      [ -f "$out" ] && bstate=file
      env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER \
          "$CC" "$opt" "${lflags[@]}" -fuse-ld=lld -shared "$obj" -o "$LTOD/$id.stock.so" \
          > /dev/null 2> "$LTOD/$id.stock.stderr.txt"
      src_rc=$?
      env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER \
          WPIN_OUT="$out" WPIN_TARGET_FNS=handle \
          "$CC" "$opt" "${lflags[@]}" -fuse-ld=lld -shared -Wl,--load-pass-plugin="$WIPEPIN" \
          "$obj" -o "$LTOD/$id.plugin.so" \
          > /dev/null 2> "$LTOD/$id.link.stderr.txt"
      lrc=$?
      lstate=absent
      [ -d "$out" ] && lstate=dir
      [ -f "$out" ] && lstate=file
      ;;
  esac
  kv "$LTOD/$id.kv" "cellId=$id" "form=$form" "what=$what" "opt=$opt" "beforeCompile=$cstate_before" \
     "compileRc=$crc" "afterCompile=$cstate" "beforeLink=$bstate" "stockLinkRc=$src_rc" \
     "pluginLinkRc=$lrc" "afterLink=$lstate" "wipepinSha256=$PIN_SHA"
  echo "$id"
}
lto lto-full-compile         full compile         -O2
lto lto-full-linkline        full linkline        -O2
lto lto-thin-linkline        thin linkline        -O2
lto lto-thin-linkline-O0     thin linkline        -O0
lto lto-full-linkline-nofile full linkline-nofile -O2
lto nopasses-ir-O2           none nopasses-ir     -O2

# ------------------------------------------------------------ xtu
# A wipe helper in another translation unit. Without LTO, use.c sees only
# secure_wipe's declaration, so the call stays, and the helper's memset -- on a
# length the helper does not know -- stays with it. An LTO link sees the
# helper's body and can inline it into handle, where the fill is a store to a
# local that dies right after it. The four units are written here on every run,
# never into the repository; the WipePinGcc loop writes the same four.
XSRC="$LAB/xtu/src"

# The helper, external. The memset is on line 3 (WipePinGcc's record carries the
# line; WipePin's has none without -g).
cat > "$XSRC/wipe.c" <<'XTU_EOF'
#include <string.h>
void secure_wipe(void *p, size_t n) {
  memset(p, 0, n);
}
XTU_EOF

# The subject, handle(): the helper's one caller, and the helper is the buffer's
# last use. The control, wipe_kept(): a memset of its own on a buffer that use()
# reads afterwards, so its fill is observable in every build and cannot be
# removed, read from the same executable by the same reader. (A first version
# routed the control through secure_wipe as well; with two callers, gcc-13 kept
# the pinned helper out of line, and the WipePinGcc loop's pinned cell could not
# show an inlining -- check-gcc-fixture-loop.py, the xtu expectations.) Both
# noinline, so that the function a fill ends up in is the same function in
# every link, whatever LTO does with main.
cat > "$XSRC/use.c" <<'XTU_EOF'
#include <string.h>
void secure_wipe(void *p, size_t n);
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
__attribute__((noinline)) void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  secure_wipe(key, sizeof key);
}
__attribute__((noinline)) void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  memset(buf, 0, sizeof buf);
  use(buf, sizeof buf);
}
XTU_EOF

cat > "$XSRC/main.c" <<'XTU_EOF'
void handle(void);
void wipe_kept(void);
int main(void) {
  handle();
  wipe_kept();
  return 0;
}
XTU_EOF

# The producer and the consumer, compiled without -flto in every cell: no link
# can see into them, so the buffers must exist in memory, and the read of the
# control's fill cannot be folded away.
cat > "$XSRC/io.c" <<'XTU_EOF'
volatile unsigned char sink;
void derive(unsigned char *k) {
  for (unsigned i = 0; i < 32; i++) k[i] = (unsigned char)(i * 7u + 1u);
}
void use(const unsigned char *k, unsigned long n) {
  for (unsigned long i = 0; i < n; i++) sink ^= k[i];
}
XTU_EOF

# xtu <id> <none|full|thin> <stock|pin|dry>
#   main.c, use.c  stock, -O2, plus -flto or -flto=thin for the form
#   wipe.c         the same; for pin and dry with WipePin loaded,
#                  WPIN_TARGET_FNS=secure_wipe, WPIN_OUT=<cell>/wipe.record.json,
#                  and WPIN_DRY_RUN=1 for dry
#   io.c           stock, -O2, never -flto
#   link           stock: -O2 and the form's LTO flag, -fuse-ld=lld, the
#                  executable <cell>/prog
# Written down, not judged: each step's rc, and whether the record is there.
xtu() {
  local id=$1 form=$2 mode=$3
  local d="$LAB/xtu/$id"
  rm -rf "$d"
  mkdir -p "$d"
  local cflags=() lflags=()
  case "$form" in
    none) ;;
    full) cflags=(-flto); lflags=(-flto) ;;
    thin) cflags=(-flto=thin); lflags=(-flto=thin -Wl,--thinlto-jobs=1) ;;
    *) echo "run-fixture-loop.sh: xtu: unknown form $form" >&2; exit 3 ;;
  esac
  local rec="$d/wipe.record.json"
  local pinenv=() pinflags=()
  case "$mode" in
    stock) ;;
    pin) pinenv=(WPIN_OUT="$rec" WPIN_TARGET_FNS=secure_wipe); pinflags=(-fpass-plugin="$WIPEPIN") ;;
    dry) pinenv=(WPIN_OUT="$rec" WPIN_TARGET_FNS=secure_wipe WPIN_DRY_RUN=1); pinflags=(-fpass-plugin="$WIPEPIN") ;;
    *) echo "run-fixture-loop.sh: xtu: unknown mode $mode" >&2; exit 3 ;;
  esac
  local clean=(env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER)
  local u rcs=()
  for u in main use; do
    "${clean[@]}" "$CC" -O2 "${cflags[@]+"${cflags[@]}"}" -c "$XSRC/$u.c" -o "$d/$u.o" 2> "$d/$u.stderr.txt"
    rcs+=("${u}Rc=$?")
  done
  "${clean[@]}" "${pinenv[@]+"${pinenv[@]}"}" \
      "$CC" -O2 "${cflags[@]+"${cflags[@]}"}" "${pinflags[@]+"${pinflags[@]}"}" \
      -c "$XSRC/wipe.c" -o "$d/wipe.o" 2> "$d/wipe.stderr.txt"
  rcs+=("wipeRc=$?")
  "${clean[@]}" "$CC" -O2 -c "$XSRC/io.c" -o "$d/io.o" 2> "$d/io.stderr.txt"
  rcs+=("ioRc=$?")
  "${clean[@]}" "$CC" -O2 "${lflags[@]+"${lflags[@]}"}" -fuse-ld=lld \
      "$d/main.o" "$d/use.o" "$d/wipe.o" "$d/io.o" -o "$d/prog" 2> "$d/link.stderr.txt"
  rcs+=("linkRc=$?")
  local recstate=not-loaded sha=not-loaded
  if [ "$mode" != stock ]; then
    recstate=absent
    [ -f "$rec" ] && recstate=file
    sha=$PIN_SHA
  fi
  kv "$LAB/xtu/$id.kv" "cellId=$id" "form=$form" "mode=$mode" "${rcs[@]}" "record=$recstate" \
     "wipepinSha256=$sha" "ccVersion=$("$CC" --version | head -n1)"
  local r
  for r in "${rcs[@]}"; do
    [ "${r#*=}" = 0 ] || { echo "run-fixture-loop.sh: $id: $r" >&2; failed=1; }
  done
  [ -f "$d/prog" ] || { echo "run-fixture-loop.sh: $id: no executable" >&2; failed=1; }
  [ "$recstate" != absent ] || { echo "run-fixture-loop.sh: $id: WipePin wrote no record" >&2; failed=1; }
  echo "$id"
}
xtu xtu-nolto none stock
for F in full thin; do
  xtu "xtu-$F-stock" "$F" stock
  xtu "xtu-$F-pin"   "$F" pin
  xtu "xtu-$F-dry"   "$F" dry
done

# ------------------------------------------------------------ v3
# Sources written here on every run, never into the repository. Each holds the
# subject handle() -- a 32-byte local filled by derive(), read by use(), then
# wiped as its last use -- and the control wipe_kept(), whose fill use() reads
# afterwards, so no build may remove it. io.c and main.c are compiled once,
# stock, and linked into every executable: derive() and use() stay opaque.
V3D="$LAB/v3"
VSRC="$V3D/src"
V3HDR='void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);'

cat > "$VSRC/memset.c" <<V3_EOF
#include <string.h>
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  memset(key, 0, sizeof key);
}
void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  memset(buf, 0, sizeof buf);
  use(buf, sizeof buf);
}
V3_EOF

cat > "$VSRC/bzero.c" <<V3_EOF
#include <strings.h>
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  bzero(key, sizeof key);
}
void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  bzero(buf, sizeof buf);
  use(buf, sizeof buf);
}
V3_EOF

# The object size through a local pointer is not folded by the front end, so
# the call reaches pipeline start as __memset_chk (measured, clang 18.1.3).
cat > "$VSRC/chk.c" <<V3_EOF
$V3HDR
void handle(void) {
  unsigned char key[32];
  unsigned char *p = key;
  derive(key);
  use(key, sizeof key);
  __builtin___memset_chk(p, 0, sizeof key, __builtin_object_size(p, 0));
}
void wipe_kept(void) {
  unsigned char buf[32];
  unsigned char *q = buf;
  derive(buf);
  __builtin___memset_chk(q, 0, sizeof buf, __builtin_object_size(q, 0));
  use(buf, sizeof buf);
}
V3_EOF

cat > "$VSRC/zcopy.c" <<V3_EOF
#include <string.h>
static const unsigned char vg_zeros[64];
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  memcpy(key, vg_zeros, sizeof key);
}
void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  memcpy(buf, vg_zeros, sizeof buf);
  use(buf, sizeof buf);
}
V3_EOF

# The wipe written as a loop of zero stores, the buffer's last use: no memset
# and no call at pipeline start, so nothing but WPIN_BUFFER_BARRIER reaches it.
# The control zeroes its buffer the same way and then reads it.
cat > "$VSRC/loop.c" <<V3_EOF
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
}
void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  for (unsigned i = 0; i < sizeof buf; i++) buf[i] = 0;
  use(buf, sizeof buf);
}
V3_EOF

# The loop wipe written through an advancing pointer, `*p++ = 0`: at pipeline
# start the pointer lives in a stack slot that each iteration reloads, advances
# and stores back. The control does the same and then reads its buffer.
cat > "$VSRC/ptr.c" <<V3_EOF
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  unsigned char *p = key;
  unsigned long n = sizeof key;
  while (n--) *p++ = 0;
}
void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  unsigned char *q = buf;
  unsigned long n = sizeof buf;
  while (n--) *q++ = 0;
  use(buf, sizeof buf);
}
V3_EOF

# An initialiser and no wipe: the buffer's one zero fill is followed by a use.
cat > "$VSRC/init.c" <<V3_EOF
$V3HDR
void handle(void) {
  unsigned char key[32] = {0};
  derive(key);
  use(key, sizeof key);
}
V3_EOF

# The same with the initialiser written as a loop of zero stores: no memset,
# so nothing for the pin either.
cat > "$VSRC/initloop.c" <<V3_EOF
$V3HDR
void handle(void) {
  unsigned char key[32];
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  derive(key);
  use(key, sizeof key);
}
V3_EOF

# A buffer declared in a loop body and wiped at the end of every iteration:
# the next iteration's derive() and use() are uses of another lifetime of the
# same alloca, not of the one the wipe ends.
cat > "$VSRC/inloop.c" <<V3_EOF
$V3HDR
void handle(int m) {
  for (int j = 0; j < m; j++) {
    unsigned char key[32];
    derive(key);
    use(key, sizeof key);
    for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  }
}
V3_EOF

# A variable-length array inside a branch, wiped by a loop: no lifetime
# markers at any level, and an alloca that dominates none of the returns.
cat > "$VSRC/vla.c" <<'V3_EOF'
void fillv(unsigned char *k, unsigned long n);
void usev(const unsigned char *k, unsigned long n);
void handle(unsigned long n, int c) {
  if (c) {
    unsigned char v[n];
    fillv(v, n);
    usev(v, n);
    for (unsigned long i = 0; i < n; i++) v[i] = 0;
  }
}
V3_EOF

# A loop wipe followed by a musttail call. At -O0 there are no lifetime
# markers, so the barrier's place is the return, and nothing may stand between
# a musttail call and its ret.
cat > "$VSRC/musttail.c" <<V3_EOF
$V3HDR
int next(int x);
int handle(int x) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  __attribute__((musttail)) return next(x);
}
V3_EOF

# Two exits from the buffer's lifetime: a return on one path, where clang ends
# the lifetime (-O1 and above), and a musttail call on the other, where clang
# puts the lifetime end after the call and its ret, in a block no path reaches.
# Both are places: the musttail call, and the lifetime end. The call to note()
# keeps the two paths from starting with the same code, which the optimiser
# would hoist into one block, the two barriers with it.
cat > "$VSRC/mtexit.c" <<V3_EOF
$V3HDR
void note(int c);
int next(int x, int c);
int handle(int x, int c) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  if (c) {
    for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
    note(c);
    return 0;
  }
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  __attribute__((musttail)) return next(x, c);
}
V3_EOF

# A wipe only on the path that ends in exit(): that path leaves the buffer's
# lifetime at no ret and no lifetime end, so it cannot be covered, and the
# buffer gets no barrier at all -- not one on the other path's lifetime end,
# which would protect no wipe and let the record say "repaired".
cat > "$VSRC/exit.c" <<V3_EOF
$V3HDR
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
V3_EOF

# A wipe loop that walks a pointer up to the buffer's end. The comparison of
# the address reads no byte of the buffer: a wipe, not an initialiser.
cat > "$VSRC/ptrcmp.c" <<V3_EOF
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  for (unsigned char *p = key; p < key + sizeof key; p++) *p = 0;
}
V3_EOF

# A variable-length array in a block, wiped by a loop, then a musttail call:
# the return is the place at every level.
cat > "$VSRC/vlamt.c" <<'V3_EOF'
void fillv(unsigned char *k, unsigned long n);
void usev(const unsigned char *k, unsigned long n);
int next(int x, unsigned long m);
int handle(int x, unsigned long m) {
  {
    unsigned char v[m];
    fillv(v, m);
    usev(v, m);
    for (unsigned long i = 0; i < m; i++) v[i] = 0;
  }
  __attribute__((musttail)) return next(x, m);
}
V3_EOF

# A copy from an all-zero constant written with __builtin_memcpy_inline, built
# -ffreestanding: llvm.memcpy.inline, which promises no library call.
cat > "$VSRC/zinline.c" <<V3_EOF
static const unsigned char vg_zeros[64];
$V3HDR
void handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, sizeof key);
  __builtin_memcpy_inline(key, vg_zeros, sizeof key);
}
V3_EOF

cat > "$VSRC/main.c" <<'V3_EOF'
void handle(void);
void wipe_kept(void);
int main(void) {
  handle();
  wipe_kept();
  return 0;
}
V3_EOF

cat > "$VSRC/io.c" <<'V3_EOF'
volatile unsigned char sink;
void derive(unsigned char *k) {
  for (unsigned i = 0; i < 32; i++) k[i] = (unsigned char)(i * 7u + 1u);
}
void use(const unsigned char *k, unsigned long n) {
  for (unsigned long i = 0; i < n; i++) sink ^= k[i];
}
V3_EOF

V3CLEAN=(env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER)
"${V3CLEAN[@]}" "$CC" -O2 -c "$VSRC/io.c" -o "$V3D/io.o" 2> "$V3D/io.stderr.txt"
V3IO_RC=$?
"${V3CLEAN[@]}" "$CC" -O2 -c "$VSRC/main.c" -o "$V3D/main.o" 2> "$V3D/main.stderr.txt"
V3MAIN_RC=$?

# v3link <prefix>: assemble <prefix>.s and link it with io.o and main.o into
# <prefix>.prog. Prints "asmRc linkRc".
v3link() {
  local pre=$1 arc lrc
  "${V3CLEAN[@]}" "$CC" -c "$pre.s" -o "$pre.o" 2> "$pre.as.stderr.txt"
  arc=$?
  "${V3CLEAN[@]}" "$CC" "$pre.o" "$V3D/io.o" "$V3D/main.o" -o "$pre.prog" 2> "$pre.link.stderr.txt"
  lrc=$?
  echo "$arc $lrc"
}

# v3case <id> <source> <switch> <cflags...>
#   the arms, each -O2 -S of <source> with <cflags>, target handle:
#   stock  no plugin                                    <id>-stock.s
#   orig   the --baseline (v2) build, clang directly    <id>-orig.s     (only with --baseline)
#   off    WipePin through pin.sh, switches unset       <id>-off.{s,json,manifest.kv,stderr.txt}
#   ext    the same with <switch>=1                     <id>-ext.*
#   dry    the same with <switch>=1 WPIN_DRY_RUN=1      <id>-dry.*
# Written down, not judged: each step's rc.
v3case() {
  local id=$1 src=$2 sw=$3
  shift 3
  local base="$V3D/$id" rcs=() r
  "${V3CLEAN[@]}" "$CC" -O2 "$@" -S "$VSRC/$src" -o "$base-stock.s" 2> "$base-stock.stderr.txt"
  rcs+=("stockRc=$?")
  if [ -n "$BASELINE" ]; then
    "${V3CLEAN[@]}" WPIN_OUT="$base-orig.json" WPIN_TARGET_FNS=handle \
        "$CC" -O2 "$@" -fpass-plugin="$BASELINE" -S "$VSRC/$src" -o "$base-orig.s" 2> "$base-orig.stderr.txt"
    rcs+=("origRc=$?")
  else
    rcs+=("origRc=not-run")
  fi
  r=$(pinsh "$V3D" "$id-off" WPIN_TARGET_FNS=handle -- -O2 "$@" -S "$VSRC/$src" -o "$base-off.s")
  rcs+=("offPinShRc=$r")
  r=$(pinsh "$V3D" "$id-ext" WPIN_TARGET_FNS=handle "$sw=1" -- -O2 "$@" -S "$VSRC/$src" -o "$base-ext.s")
  rcs+=("extPinShRc=$r")
  r=$(pinsh "$V3D" "$id-dry" WPIN_TARGET_FNS=handle "$sw=1" WPIN_DRY_RUN=1 -- -O2 "$@" -S "$VSRC/$src" -o "$base-dry.s")
  rcs+=("dryPinShRc=$r")
  local arm lk
  for arm in stock off ext dry; do
    lk=$(v3link "$base-$arm")
    rcs+=("${arm}AsmRc=${lk% *}" "${arm}LinkRc=${lk#* }")
  done
  kv "$V3D/$id.kv" "cellId=$id" "source=$src" "switch=$sw" "cflags=$*" "baseline=${BASELINE:+present}" \
     "baselineSha256=$([ -n "$BASELINE" ] && sha256sum "$BASELINE" | cut -d' ' -f1)" \
     "ioRc=$V3IO_RC" "mainRc=$V3MAIN_RC" "${rcs[@]}" "wipepinSha256=$PIN_SHA"
  echo "$id"
}
v3case v3-fort2       memset.c WPIN_BARRIER_CALLS -D_FORTIFY_SOURCE=2
v3case v3-fort3       memset.c WPIN_BARRIER_CALLS -D_FORTIFY_SOURCE=3
v3case v3-bzero-fort2 bzero.c  WPIN_BARRIER_CALLS -D_FORTIFY_SOURCE=2
v3case v3-bzero-fort3 bzero.c  WPIN_BARRIER_CALLS -D_FORTIFY_SOURCE=3
v3case v3-chk         chk.c    WPIN_BARRIER_CALLS
v3case v3-libcall     memset.c WPIN_BARRIER_CALLS -fno-builtin
v3case v3-zcopy       zcopy.c  WPIN_ZERO_COPY
v3case v3-zcopy-fort2 zcopy.c  WPIN_ZERO_COPY -D_FORTIFY_SOURCE=2
v3case v3-loop        loop.c   WPIN_BUFFER_BARRIER
v3case v3-loop-g      loop.c   WPIN_BUFFER_BARRIER -g
v3case v3-loop-ptr    ptr.c    WPIN_BUFFER_BARRIER

# The buffer barrier on an initialiser: pin.sh alone, -O2 -S, target handle,
# WPIN_BUFFER_BARRIER=1, beside a stock -S of the same source.
"${V3CLEAN[@]}" "$CC" -O2 -S "$VSRC/init.c" -o "$V3D/v3-buffer-init-stock.s" 2> "$V3D/v3-buffer-init-stock.stderr.txt"
V3INIT_STOCK_RC=$?
V3INIT_RC=$(pinsh "$V3D" v3-buffer-init WPIN_TARGET_FNS=handle WPIN_BUFFER_BARRIER=1 -- -O2 -S "$VSRC/init.c" \
              -o "$V3D/v3-buffer-init.s")
kv "$V3D/v3-buffer-init.kv" "cellId=v3-buffer-init" "source=init.c" "setting=WPIN_BUFFER_BARRIER=1" \
   "stockRc=$V3INIT_STOCK_RC" "pinShRc=$V3INIT_RC" "wipepinSha256=$PIN_SHA"
echo v3-buffer-init

# Where a barrier must not go and what it must not cover, and the inline copy.
# Each through pin.sh alone, target handle, twice -- -S, which runs the
# backend, and -S -emit-llvm, whose output the IR verifier then reads (a
# release clang does not verify the IR the plugin leaves) -- beside a stock -S.
V3OPT=${WPIN_OPT:-opt-$("$CC" -dumpversion 2>/dev/null | cut -d. -f1)}
# v3single <id> <source> [VAR=VAL ...] -- <clang flags...>
v3single() {
  local id=$1 src=$2 envs=() rc llrc stockrc vrc
  shift 2
  while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  "${V3CLEAN[@]}" "$CC" "$@" -S "$VSRC/$src" -o "$V3D/$id-stock.s" 2> "$V3D/$id-stock.stderr.txt"
  stockrc=$?
  rc=$(pinsh "$V3D" "$id" WPIN_TARGET_FNS=handle "${envs[@]}" -- "$@" -S "$VSRC/$src" -o "$V3D/$id.s")
  llrc=$(pinsh "$V3D" "$id-ll" WPIN_TARGET_FNS=handle "${envs[@]}" -- "$@" -S -emit-llvm "$VSRC/$src" -o "$V3D/$id.ll")
  if [ -s "$V3D/$id.ll" ]; then
    "$V3OPT" -passes=verify -disable-output "$V3D/$id.ll" > "$V3D/$id.verify.txt" 2>&1
    vrc=$?
  else
    vrc=no-ll
  fi
  kv "$V3D/$id.kv" "cellId=$id" "source=$src" "setting=${envs[*]}" "cflags=$*" "stockRc=$stockrc" \
     "pinShRc=$rc" "llPinShRc=$llrc" "verifyRc=$vrc" "opt=$V3OPT" "wipepinSha256=$PIN_SHA"
  echo "$id"
}
v3single v3-vla-branch-O0   vla.c      WPIN_BUFFER_BARRIER=1 -- -O0
v3single v3-vla-branch-O2   vla.c      WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-musttail-O0     musttail.c WPIN_BUFFER_BARRIER=1 -- -O0
v3single v3-vla-musttail-O2 vlamt.c    WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-musttail-O2     musttail.c WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-musttail-Os     musttail.c WPIN_BUFFER_BARRIER=1 -- -Os
v3single v3-musttail-exits-O2 mtexit.c WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-loop-ptrcmp-O2  ptrcmp.c   WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-exit-O2         exit.c     WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-buffer-initloop initloop.c WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-buffer-inloop   inloop.c   WPIN_BUFFER_BARRIER=1 -- -O2
v3single v3-zcopy-inline    zinline.c  WPIN_ZERO_COPY=1 -- -O2 -ffreestanding

# pin.sh where the configuration must be refused: no record, exit 3.
v3refuse() {
  local id=$1 setting=$2 rc
  rc=$(pinsh "$V3D" "$id" WPIN_TARGET_FNS=handle "$setting" -- -O2 -c "$VSRC/memset.c" -o "$V3D/$id.o")
  kv "$V3D/$id.kv" "cellId=$id" "setting=$setting" "pinShRc=$rc" "wipepinSha256=$PIN_SHA"
  echo "$id"
}
v3refuse v3-refuse-barrier2      WPIN_BARRIER_CALLS=2
v3refuse v3-refuse-zerocopy-true WPIN_ZERO_COPY=true
v3refuse v3-refuse-buffer2       WPIN_BUFFER_BARRIER=2

# The handshake. The trailing shape's front-end IR (-O2, no LLVM passes) is
# compiled back with -x ir: as written, with its !llvm.ident rewritten to name
# the next major version of clang (19.1.1 when $CC is clang-18), and with
# !llvm.ident removed. Only the metadata differs. Each is compiled -S twice:
# through pin.sh, and stock, so that the checker can see that a refused module
# was left exactly as a stock compile leaves it.
"${V3CLEAN[@]}" "$CC" -O2 -Xclang -disable-llvm-passes -S -emit-llvm "$SRC/trailing.c" -o "$V3D/ident-fe.ll" \
    2> "$V3D/ident-fe.stderr.txt"
V3FE_RC=$?
V3CC_MAJOR=$("$CC" -dumpversion 2>/dev/null | cut -d. -f1)
V3OTHER="$(( ${V3CC_MAJOR:-0} + 1 )).1.1"
sed -e 's/^\(![0-9]* = !{!"\)[^"]*clang version [^"]*"/\1clang version '"$V3OTHER"'"/' "$V3D/ident-fe.ll" \
    > "$V3D/ident-other.ll"
grep -v '^!llvm.ident' "$V3D/ident-fe.ll" > "$V3D/ident-none.ll"
v3ident() {
  local id=$1 ll=$2 rc src
  "${V3CLEAN[@]}" "$CC" -O2 -x ir -S "$V3D/$ll" -o "$V3D/$id-stock.s" 2> "$V3D/$id-stock.stderr.txt"
  src=$?
  rc=$(pinsh "$V3D" "$id" WPIN_TARGET_FNS=handle -- -O2 -x ir -S "$V3D/$ll" -o "$V3D/$id.s")
  kv "$V3D/$id.kv" "cellId=$id" "input=$ll" "frontEndRc=$V3FE_RC" "stockRc=$src" "pinShRc=$rc" \
     "ccMajor=$V3CC_MAJOR" "identLines=$(grep -c '^!llvm.ident' "$V3D/$ll")" "wipepinSha256=$PIN_SHA"
  echo "$id"
}
v3ident v3-ident-same  ident-fe.ll
v3ident v3-ident-other ident-other.ll
v3ident v3-ident-none  ident-none.ll

if [ $failed -ne 0 ]; then
  echo "run-fixture-loop.sh: at least one cell did not produce its records" >&2
  exit 3
fi
exit 0
