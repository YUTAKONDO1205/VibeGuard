#!/bin/bash
# The fixture loop for WipePinGcc: compile the erasure fixture with and without
# the plugin, at every level, and leave everything a grader needs in the lab.
#
#   run-gcc-fixture-loop.sh --lab DIR --plugin libWipePinGcc.so
#
# (or WPIN_LAB / WPIN_PLUGIN in the environment). There are no default paths:
# where the lab and the build live is the caller's business.
#
# Reads:   the erasure fixture written by compiler/llvm-pass/tools/make-fixtures.sh,
#          generated into <lab>/fixtures on every run -- never into the repo --
#          and the shape sources below, written into <lab>/shapes/src.
# Writes:  <lab>/asm/<cell>.s          the -S listing the grader reads
#          <lab>/obj/<cell>.o          the -c object, for byte comparison
#          <lab>/records/<cell>.s.json WipePinGcc's record from the -S compile
#          <lab>/pinsh/<cell>.*        the -c compile, run through pin-gcc.sh
#          <lab>/cells/<cell>.kv       what ran, with the plugin's sha256
#          <lab>/stderr/<cell>.*.txt   the compiler's stderr
#          <lab>/alone/  <lab>/shapes/  <lab>/stale/
# Decides: nothing. check-gcc-fixture-loop.py grades, and it compiles nothing,
#          so the code that produces a listing is not the code that says what
#          the listing shows.
#
# Four groups of cells:
#
#   loop    the erasure fixture's target.c at -O0 -O1 -O2 -O3 -Os, five ways:
#             base       no plugin
#             pin        WPIN_TARGET_FNS=handle_request
#             dry        the same, WPIN_DRY_RUN=1 (the red control)
#             wrongname  WPIN_TARGET_FNS=handle_requestX
#             nothing    the fixture's opaque.c, which holds no memset at all,
#                        in module scope, beside nothing-base (opaque.c without
#                        the plugin): loaded with nothing to pin
#           Every plugin cell is compiled twice with the same settings: -S
#           directly (the listing), and -c through pin-gcc.sh (the object, the
#           exit code, the manifest). The two records must be the same record.
#   alone   pin-gcc.sh where it must exit 3 (no target, -fsyntax-only, a
#           WPIN_DRY_RUN that is neither 0 nor 1), and two source files on one
#           line, where the last one's record is the one left.
#   shapes  small sources, -O2 -g (loopreturn at every level), each with a
#           known reading of the record: see the comments above each one.
#   stale   the compiler run directly (not pin-gcc.sh, which deletes the path
#           itself) with something that is not this compile's record already at
#           WPIN_OUT.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COMPILER=$(cd "$HERE/../.." && pwd)

LAB=${WPIN_LAB:-}
PLUGIN=${WPIN_PLUGIN:-}
CC=${WPIN_CC:-gcc-13}
PINSH="$HERE/pin-gcc.sh"

usage() {
  echo "usage: run-gcc-fixture-loop.sh --lab DIR --plugin libWipePinGcc.so" >&2
  exit 3
}

while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB=${2:-}; shift 2 || usage ;;
    --plugin) PLUGIN=${2:-}; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$LAB" ] && [ -n "$PLUGIN" ] || usage
[ -f "$PLUGIN" ] || { echo "run-gcc-fixture-loop.sh: no plugin at $PLUGIN" >&2; exit 3; }
mkdir -p "$LAB"
LAB=$(cd "$LAB" && pwd)
PLUGIN=$(cd "$(dirname "$PLUGIN")" && pwd)/$(basename "$PLUGIN")

IRCK_LAB="$LAB" bash "$COMPILER/llvm-pass/tools/make-fixtures.sh" >/dev/null
FX="$LAB/fixtures/erasure"
[ -f "$FX/target.c" ] && [ -f "$FX/opaque.c" ] || {
  echo "run-gcc-fixture-loop.sh: fixture generation failed" >&2; exit 3; }

rm -rf "$LAB/asm" "$LAB/obj" "$LAB/records" "$LAB/pinsh" "$LAB/cells" "$LAB/stderr" \
       "$LAB/alone" "$LAB/shapes" "$LAB/stale"
mkdir -p "$LAB/asm" "$LAB/obj" "$LAB/records" "$LAB/pinsh" "$LAB/cells" "$LAB/stderr" \
         "$LAB/alone" "$LAB/shapes/src" "$LAB/stale"
PIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)
CC_VERSION=$("$CC" --version | head -n1)
LEVELS="-O0 -O1 -O2 -O3 -Os"

failed=0

# kv <file> <key=value ...>
kv() { local f=$1; shift; printf '%s\n' "$@" > "$f"; }

# Nothing from the caller's environment may configure the plugin in a cell
# that did not ask for it, and nothing may leak from one cell into the next.
CLEAN=(env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN)

# pinsh <dir> <id> [VAR=VAL ...] -- <gcc args...>
#   pin-gcc.sh with only the settings given here. Prints its exit code; its
#   files land at <dir>/<id>.{json,manifest.kv,stderr.txt}, and everything it
#   printed at <dir>/<id>.console.txt.
pinsh() {
  local dir=$1 id=$2
  shift 2
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  "${CLEAN[@]}" WPIN_CC="$CC" "${envs[@]+"${envs[@]}"}" \
      bash "$PINSH" "$PLUGIN" "$dir/$id.json" "$@" > /dev/null 2> "$dir/$id.console.txt"
  echo $?
}

# plain <cell-id> <opt> <source>: no plugin, -S and -c.
plain() {
  local id=$1 opt=$2 src=$3
  "${CLEAN[@]}" "$CC" "$opt" -S "$src" -o "$LAB/asm/$id.s" 2> "$LAB/stderr/$id.s.txt"
  local rs=$?
  "${CLEAN[@]}" "$CC" "$opt" -c "$src" -o "$LAB/obj/$id.o" 2> "$LAB/stderr/$id.o.txt"
  local rc=$?
  kv "$LAB/cells/$id.kv" "cellId=$id" "opt=$opt" "source=$(basename "$src")" "mode=plain" \
     "asmRc=$rs" "objRc=$rc" "pinShRc=not-run" "pluginSha256=not-loaded" "ccVersion=$CC_VERSION" "env="
  [ $rs -eq 0 ] && [ $rc -eq 0 ] || { echo "run-gcc-fixture-loop.sh: $id: rc $rs/$rc" >&2; failed=1; }
  echo "$id"
}

# withplugin <cell-id> <opt> <source> [VAR=VAL ...]: -S directly, -c through pin-gcc.sh.
withplugin() {
  local id=$1 opt=$2 src=$3
  shift 3
  local rec="$LAB/records/$id.s.json"
  rm -f "$rec"
  "${CLEAN[@]}" WPIN_OUT="$rec" "$@" \
      "$CC" -fplugin="$PLUGIN" "$opt" -S "$src" -o "$LAB/asm/$id.s" 2> "$LAB/stderr/$id.s.txt"
  local rs=$?
  local prc
  prc=$(pinsh "$LAB/pinsh" "$id" "$@" -- "$opt" -c "$src" -o "$LAB/obj/$id.o")
  kv "$LAB/cells/$id.kv" "cellId=$id" "opt=$opt" "source=$(basename "$src")" "mode=plugin" \
     "asmRc=$rs" "objRc=see-pinsh" "pinShRc=$prc" "pluginSha256=$PIN_SHA" "ccVersion=$CC_VERSION" "env=$*"
  [ $rs -eq 0 ] || { echo "run-gcc-fixture-loop.sh: $id: -S rc $rs" >&2; failed=1; }
  echo "$id"
}

for O in $LEVELS; do
  plain      "base$O"          "$O" "$FX/target.c"
  withplugin "pin$O"           "$O" "$FX/target.c" WPIN_TARGET_FNS=handle_request
  withplugin "dry$O"           "$O" "$FX/target.c" WPIN_TARGET_FNS=handle_request WPIN_DRY_RUN=1
  withplugin "wrongname$O"     "$O" "$FX/target.c" WPIN_TARGET_FNS=handle_requestX
  plain      "nothing-base$O"  "$O" "$FX/opaque.c"
  withplugin "nothing$O"       "$O" "$FX/opaque.c" WPIN_SCOPE=module
done

# ------------------------------------------------------------ pin-gcc.sh alone
rc=$(pinsh "$LAB/alone" notarget-O2 -- -O2 -c "$FX/target.c" -o "$LAB/alone/notarget-O2.o")
kv "$LAB/alone/notarget-O2.kv" "cellId=notarget-O2" "pinShRc=$rc" "pluginSha256=$PIN_SHA"
echo notarget-O2
rc=$(pinsh "$LAB/alone" syntaxonly-O2 WPIN_TARGET_FNS=handle_request -- \
       -O2 -fsyntax-only "$FX/target.c")
kv "$LAB/alone/syntaxonly-O2.kv" "cellId=syntaxonly-O2" "pinShRc=$rc" "pluginSha256=$PIN_SHA"
echo syntaxonly-O2
rc=$(pinsh "$LAB/alone" baddry-O2 WPIN_TARGET_FNS=handle_request WPIN_DRY_RUN=yes -- \
       -O2 -c "$FX/target.c" -o "$LAB/alone/baddry-O2.o")
kv "$LAB/alone/baddry-O2.kv" "cellId=baddry-O2" "pinShRc=$rc" "pluginSha256=$PIN_SHA"
echo baddry-O2
# Two source files: the driver runs one cc1 per file, in order. The objects go
# next to the working directory, so the compile runs inside alone/two.
mkdir -p "$LAB/alone/two"
rc=$(cd "$LAB/alone/two" && pinsh "$LAB/alone" twosources-O2 WPIN_TARGET_FNS=handle_request -- \
       -O2 -c "$FX/target.c" "$FX/opaque.c")
kv "$LAB/alone/twosources-O2.kv" "cellId=twosources-O2" "pinShRc=$rc" "pluginSha256=$PIN_SHA"
echo twosources-O2

# ------------------------------------------------------------ shapes
# Each source is one function `handle` (or a named inline target) holding one
# 32-byte stack buffer that an opaque external function fills and another
# reads. Written here on every run, never into the repository.
SRC="$LAB/shapes/src"

# The initialiser and a zeroing loop. clang lowers `= {0}` to a zero-fill
# llvm.memset and WipePin pins it (followedByUse true, the partial line). GCC
# lowers it to the aggregate assignment `key = {}`, which is not a memset call:
# nothing in scope to pin, and pin-gcc.sh exits 4.
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

# The initialiser again, and the wipe in a static helper. The helper's memset
# is out of scope; the target has no memset of its own.
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

# A clear-before-fill memset and a trailing wipe memset on one buffer: two
# sites, the first followed by a use, the second not.
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

# The clear-before-fill memset again, every later use through a copy of the
# address held in another local: followedByUse must follow the copy.
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

# A return from inside a loop, the wipe on the error path, and a trailing wipe.
# The shape of fable_N_token_r3's line 17, where clang's cleanup dispatch gives
# the return a CFG edge back into the loop. `n` has its address taken, so the
# loop body's scope has a clobber to run on the way out -- the try/finally that
# GCC lowers, at -O0 and at -O1+ possibly differently. Neither wipe is followed
# by a use of token on any path the program can take.
cat > "$SRC/loopreturn.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
long emit(int fd, const unsigned char *p, unsigned long n, long *wrote);
int handle(int fd) {
  unsigned char token[32];
  derive(token);
  unsigned long total = 0;
  while (total < sizeof token) {
    long n;
    if (emit(fd, token + total, sizeof token - total, &n) < 0) {
      memset(token, 0, sizeof token);
      return -1;
    }
    total += (unsigned long)n;
  }
  memset(token, 0, sizeof token);
  return 0;
}
SHAPE_EOF

# A wipe the source already pinned, with a barrier of its own directly after
# it. Recorded as alreadyVolatile and left alone, so nothing is pinned. The
# barrier names the buffer, and the contract counts any later statement that
# names it as a use: followedByUse is true, and the partial line says so.
cat > "$SRC/srcbarrier.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  memset(key, 0, sizeof key);
  __asm__ __volatile__("" : : "r"(key) : "memory");
  return 0;
}
SHAPE_EOF

# A C99 inline definition (no extern declaration in this unit): in GCC a
# DECL_EXTERNAL function with a body, never emitted here.
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

# A C++ inline function, with C language linkage so its symbol is its name.
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

# Counted, not ignored: -fno-builtin makes memset an ordinary call.
cp "$SRC/trailing.c" "$SRC/nobuiltin.c"

# Counted, not ignored: two fills that are not zero, next to one trailing wipe.
cat > "$SRC/nonzero.c" <<'SHAPE_EOF'
#include <string.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(int c) {
  unsigned char key[32];
  unsigned char pad[32];
  memset(pad, 0xAA, sizeof pad);
  memset(key, c, sizeof key);
  derive(key);
  use(key, 32);
  use(pad, 32);
  memset(key, 0, sizeof key);
  return 0;
}
SHAPE_EOF

# Counted, not ignored: the checked memset written out, as a fortifying header
# writes it inside its wrapper, with an object size nothing can know before
# the object-size pass runs.
cat > "$SRC/chk.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
int handle(unsigned char *p, unsigned long n) {
  derive(p);
  use(p, n);
  __builtin___memset_chk(p, 0, n, __builtin_dynamic_object_size(p, 0));
  return 0;
}
SHAPE_EOF

# The checked memset again, on a local array, where the object size is a
# constant the front end knows. Measured: gcc-13 folds this one into a plain
# __builtin_memset before the pass runs, so it is a site like any other and is
# pinned; memsetChk stays 0.
cat > "$SRC/chkconst.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  __builtin___memset_chk(key, 0, sizeof key, __builtin_object_size(key, 0));
  return 0;
}
SHAPE_EOF

# shape <id> <source> <target> <opt> [extra gcc flags...]: -g -S, pin-gcc.sh's exit code kept.
shape() {
  local id=$1 src=$2 target=$3 opt=$4
  shift 4
  local rc
  rc=$(pinsh "$LAB/shapes" "$id" WPIN_TARGET_FNS="$target" -- \
         "$opt" -g "$@" -S "$SRC/$src" -o "$LAB/shapes/$id.s")
  kv "$LAB/shapes/$id.kv" "cellId=$id" "source=$src" "target=$target" "opt=$opt" \
     "flags=$*" "pinShRc=$rc" "pluginSha256=$PIN_SHA"
  echo "$id"
}
shape initloop   initloop.c    handle      -O2
shape inithelper inithelper.c  handle      -O2
shape initwipe   initwipe.c    handle      -O2
shape aliasinit  aliasinit.c   handle      -O2
shape trailing   trailing.c    handle      -O2
for O in $LEVELS; do
  shape "loopreturn$O" loopreturn.c handle "$O"
done
shape srcbarrier srcbarrier.c  handle      -O2
shape c99inline  c99inline.c   wipe_inline -O2
shape cxxinline  cxxinline.cpp wipe_cxx    -O2
shape nobuiltin  nobuiltin.c   handle      -O2 -fno-builtin
shape nonzero    nonzero.c     handle      -O2
shape chk        chk.c         handle      -O2
shape chkconst   chkconst.c    handle      -O2

# ------------------------------------------------------------ stale records
# stale <id> <what-is-at-WPIN_OUT: file|dir> [VAR=VAL ...] -- <gcc args...>
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
  "${CLEAN[@]}" WPIN_OUT="$out" "${envs[@]+"${envs[@]}"}" \
      "$CC" -fplugin="$PLUGIN" "$@" > /dev/null 2> "$LAB/stale/$id.stderr.txt"
  local rc=$?
  local state=absent
  [ -d "$out" ] && state=dir
  [ -f "$out" ] && state=file
  kv "$LAB/stale/$id.kv" "cellId=$id" "before=$what" "rc=$rc" "after=$state" \
     "pluginSha256=$PIN_SHA"
  echo "$id"
}
stale stale-refused    file -- -O2 -c "$SRC/trailing.c" -o "$LAB/stale/stale-refused.o"
stale stale-syntaxonly file WPIN_TARGET_FNS=handle -- -O2 -fsyntax-only "$SRC/trailing.c"
stale stale-live       file WPIN_TARGET_FNS=handle -- -O2 -c "$SRC/trailing.c" -o "$LAB/stale/stale-live.o"
stale stale-dir        dir  WPIN_TARGET_FNS=handle -- -O2 -c "$SRC/trailing.c" -o "$LAB/stale/stale-dir.o"

if [ $failed -ne 0 ]; then
  echo "run-gcc-fixture-loop.sh: at least one cell did not compile" >&2
  exit 3
fi
exit 0
