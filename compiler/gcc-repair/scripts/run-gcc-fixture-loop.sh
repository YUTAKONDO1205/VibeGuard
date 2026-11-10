#!/bin/bash
# The fixture loop for WipePinGcc: compile the erasure fixture with and without
# the plugin, at every level, and leave everything a grader needs in the lab.
#
#   run-gcc-fixture-loop.sh --lab DIR --plugin libWipePinGcc.so
#                           [--previous-plugin libWipePinGcc.so]
#
# (or WPIN_LAB / WPIN_PLUGIN / WPIN_PREVIOUS_PLUGIN in the environment). There
# are no default paths: where the lab and the builds live is the caller's
# business.
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
#          <lab>/alone/  <lab>/shapes/  <lab>/stale/  <lab>/lto/  <lab>/xtu/
#          <lab>/switch/  <lab>/buffer/  <lab>/previous/
# Decides: nothing. check-gcc-fixture-loop.py grades, and it compiles nothing,
#          so the code that produces a listing is not the code that says what
#          the listing shows.
#
# Every cell of the first six groups runs with the three switches of
# compiler/schema/wipe-pin.md section 14.2 (WPIN_BARRIER_CALLS, WPIN_ZERO_COPY,
# WPIN_BUFFER_BARRIER) unset, except the alone cells that set one to a value
# the plugin must refuse. The switch and buffer groups are the only ones that
# turn any on.
#
# Nine groups of cells:
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
#           WPIN_DRY_RUN that is neither 0 nor 1, and each switch set to 2),
#           and two source files on one line, where the last one's record is
#           the one left.
#   shapes  small sources, -O2 -g (loopreturn at every level), each with a
#           known reading of the record: see the comments above each one. The
#           barrier shapes (srcbarrier, clobonly, otherbar) are also compiled
#           without the plugin, into <lab>/shapes/<id>-stock.s, so that the
#           zero store can be read from both listings.
#   stale   the compiler run directly (not pin-gcc.sh, which deletes the path
#           itself) with something that is not this compile's record already at
#           WPIN_OUT.
#   lto     the trailing shape at -O2: an -flto compile with the plugin, a link
#           of that object with the plugin on the link line and the same
#           WPIN_OUT, and stock -flto links of the pinned and of an unpinned
#           object, disassembled with objdump into <lab>/lto/*.objdump.txt.
#   xtu     a wipe helper in another translation unit: secure_wipe(p, n) in
#           wipe.c, called on a local buffer's last use by handle() in use.c,
#           with main.c and io.c (the producer and consumer, never compiled
#           -flto), linked into an executable at -O2 -- stock without LTO, and
#           with -flto a stock build, a build with the plugin at the compile of
#           wipe.c only, and the same as a dry run. The loss here is one only
#           the LTO link can create, by inlining the helper; the checker reads
#           the executable itself. The same four sources as the WipePin loop's.
#   switch  the shapes the two switches exist for, -O2 without -g, each
#           compiled four ways into <lab>/switch: stock (no plugin), off (the
#           plugin, no switch), on (its switch =1) and dry (the switch and
#           WPIN_DRY_RUN=1), the plugin cells through pin-gcc.sh:
#             bzero     a trailing bzero(key, 32) under the default
#                       _FORTIFY_SOURCE, which makes it a call of the header's
#                       bzero wrapper (WPIN_BARRIER_CALLS)
#             chkvar    __builtin___memset_chk on a local array with a length
#                       that is not a constant (WPIN_BARRIER_CALLS)
#             zcopyagg  memcpy(key, vg_zeros, 32) from an all-zero read-only
#                       static, -U_FORTIFY_SOURCE: the aggregate copy the
#                       gimplifier makes of it (WPIN_ZERO_COPY)
#             zcopyhdr  the same source under the default _FORTIFY_SOURCE: the
#                       header's memcpy wrapper (WPIN_ZERO_COPY)
#   buffer  the buffer barrier (WPIN_BUFFER_BARRIER), -O2 without -g, into
#           <lab>/buffer:
#             loopbar   a wipe written as a loop of zero stores, the buffer's
#                       last use, beside a control wipe_kept that zeroes its
#                       buffer the same way and then reads it: stock, off, on
#                       and dry, as the switch cells
#             initbar   `= {0}` followed by uses and no wipe: stock, and on
#             inloop    a buffer declared in a loop body, filled, read and
#                       wiped by a loop of zero stores in every iteration,
#                       beside the same control: stock, and on
#             initzero  a loop of zero stores as an initialiser, followed by
#                       uses and no wipe: stock, and on
#   previous  only with --previous-plugin: every plugin compile of the loop,
#           shapes, switch-off and buffer-off cells again, -S, once with this
#           plugin and
#           once with the previous one, each copied in turn to the same path so
#           that the plugin's path cannot be what differs. With every switch
#           off the two listings must be the same bytes. Without the option the
#           group is not run, and the checker says so.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COMPILER=$(cd "$HERE/../.." && pwd)

LAB=${WPIN_LAB:-}
PLUGIN=${WPIN_PLUGIN:-}
PREV=${WPIN_PREVIOUS_PLUGIN:-}
CC=${WPIN_CC:-gcc-13}
PINSH="$HERE/pin-gcc.sh"

usage() {
  echo "usage: run-gcc-fixture-loop.sh --lab DIR --plugin libWipePinGcc.so [--previous-plugin libWipePinGcc.so]" >&2
  exit 3
}

while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB=${2:-}; shift 2 || usage ;;
    --plugin) PLUGIN=${2:-}; shift 2 || usage ;;
    --previous-plugin) PREV=${2:-}; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$LAB" ] && [ -n "$PLUGIN" ] || usage
[ -f "$PLUGIN" ] || { echo "run-gcc-fixture-loop.sh: no plugin at $PLUGIN" >&2; exit 3; }
if [ -n "$PREV" ]; then
  [ -f "$PREV" ] || { echo "run-gcc-fixture-loop.sh: no previous plugin at $PREV" >&2; exit 3; }
  PREV=$(cd "$(dirname "$PREV")" && pwd)/$(basename "$PREV")
fi
mkdir -p "$LAB"
LAB=$(cd "$LAB" && pwd)
PLUGIN=$(cd "$(dirname "$PLUGIN")" && pwd)/$(basename "$PLUGIN")

IRCK_LAB="$LAB" bash "$COMPILER/llvm-pass/tools/make-fixtures.sh" >/dev/null
FX="$LAB/fixtures/erasure"
[ -f "$FX/target.c" ] && [ -f "$FX/opaque.c" ] || {
  echo "run-gcc-fixture-loop.sh: fixture generation failed" >&2; exit 3; }

rm -rf "$LAB/asm" "$LAB/obj" "$LAB/records" "$LAB/pinsh" "$LAB/cells" "$LAB/stderr" \
       "$LAB/alone" "$LAB/shapes" "$LAB/stale" "$LAB/lto" "$LAB/xtu" "$LAB/switch" "$LAB/buffer" "$LAB/previous"
mkdir -p "$LAB/asm" "$LAB/obj" "$LAB/records" "$LAB/pinsh" "$LAB/cells" "$LAB/stderr" \
         "$LAB/alone" "$LAB/shapes/src" "$LAB/stale" "$LAB/lto" "$LAB/xtu/src" "$LAB/switch" "$LAB/buffer"
PIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)
CC_VERSION=$("$CC" --version | head -n1)
LEVELS="-O0 -O1 -O2 -O3 -Os"

failed=0

# kv <file> <key=value ...>
kv() { local f=$1; shift; printf '%s\n' "$@" > "$f"; }

# Nothing from the caller's environment may configure the plugin in a cell
# that did not ask for it, and nothing may leak from one cell into the next.
CLEAN=(env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN
       -u WPIN_BARRIER_CALLS -u WPIN_ZERO_COPY -u WPIN_BUFFER_BARRIER)

# ------------------------------------------------------------ previous plugin
# prevpair <id> <source> <opt> [VAR=VAL ...] -- [gcc flags...]
#   With --previous-plugin: the same -S compile twice, with this plugin and
#   with the previous one, each first copied to <lab>/previous/stage/, so that
#   the -fplugin= path on the two command lines is the same string. Listings
#   at <lab>/previous/{this,prev}/<id>.s; the ids, in order, in
#   <lab>/previous/cells.txt. Without the option, nothing.
STAGE="$LAB/previous/stage/libWipePinGcc.so"
if [ -n "$PREV" ]; then
  mkdir -p "$LAB/previous/stage" "$LAB/previous/this" "$LAB/previous/prev"
  : > "$LAB/previous/cells.txt"
  kv "$LAB/previous/given.kv" "pluginSha256=$PIN_SHA" "previousSha256=$(sha256sum "$PREV" | cut -d' ' -f1)" \
     "ccVersion=$CC_VERSION"
fi
prevpair() {
  [ -n "$PREV" ] || return 0
  local id=$1 src=$2 opt=$3
  shift 3
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  local which so rcs=()
  for which in this prev; do
    so=$PLUGIN
    [ "$which" = prev ] && so=$PREV
    cp "$so" "$STAGE"
    "${CLEAN[@]}" WPIN_OUT="$LAB/previous/$which/$id.json" "${envs[@]+"${envs[@]}"}" \
        "$CC" -fplugin="$STAGE" "$opt" "$@" -S "$src" -o "$LAB/previous/$which/$id.s" \
        2> "$LAB/previous/$which/$id.stderr.txt"
    rcs+=("${which}Rc=$?" "${which}StagedSha256=$(sha256sum "$STAGE" | cut -d' ' -f1)")
  done
  kv "$LAB/previous/$id.kv" "cellId=$id" "source=$(basename "$src")" "opt=$opt" "flags=$*" \
     "env=${envs[*]+"${envs[*]}"}" "${rcs[@]}"
  echo "$id" >> "$LAB/previous/cells.txt"
}

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
  prevpair "$id" "$src" "$opt" "$@" --
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
# The three switches of compiler/schema/wipe-pin.md section 14.2, each set to a
# value that is neither 0 nor 1.
for spec in badbarrier-O2:WPIN_BARRIER_CALLS=2 badzerocopy-O2:WPIN_ZERO_COPY=2 \
            badbuffer-O2:WPIN_BUFFER_BARRIER=2; do
  id=${spec%%:*}
  rc=$(pinsh "$LAB/alone" "$id" WPIN_TARGET_FNS=handle_request "${spec#*:}" -- \
         -O2 -c "$FX/target.c" -o "$LAB/alone/$id.o")
  kv "$LAB/alone/$id.kv" "cellId=$id" "pinShRc=$rc" "pluginSha256=$PIN_SHA" "env=${spec#*:}"
  echo "$id"
done
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
# it: volatile, a "memory" clobber, and the buffer as an input operand -- the
# form of the plugin's own pin. Recorded as alreadyVolatile and left alone, so
# nothing is pinned. The barrier names the buffer, and any later statement that
# names it is a use (compiler/schema/wipe-pin.md section 8): followedByUse is
# true, and the partial line says so. The zero store is in the listing with
# and without the plugin: the source's barrier keeps it.
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

# A barrier that is not a pin: volatile, a "memory" clobber, and no operand at
# all. The local's address never leaves the function, so the clobber does not
# make the zero store observable, and gcc-13 -O2 deletes it (the stock
# listing). The plugin must pin this site: alreadyVolatile false, one pin, and
# the zero store back in the listing.
cat > "$SRC/clobonly.c" <<'SHAPE_EOF'
#include <string.h>
#include <stdint.h>
uint64_t get(void);
void consume(uint64_t);
int handle(void) {
  uint64_t k = get();
  consume(k);
  memset(&k, 0, sizeof k);
  __asm__ __volatile__("" ::: "memory");
  return 0;
}
SHAPE_EOF

# The same, with a barrier that names a different local: its input operand is
# not the memset's destination, so it is not a pin of this site either.
cat > "$SRC/otherbar.c" <<'SHAPE_EOF'
#include <string.h>
#include <stdint.h>
uint64_t get(void);
void consume(uint64_t);
int handle(void) {
  uint64_t k = get();
  uint64_t other = get();
  consume(k);
  consume(other);
  memset(&k, 0, sizeof k);
  __asm__ __volatile__("" : : "g"(&other) : "memory");
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
  prevpair "shape-$id" "$SRC/$src" "$opt" WPIN_TARGET_FNS="$target" -- -g "$@"
  echo "$id"
}
# stock <id> <source> <opt>: the same -g -S compile without the plugin, into
# <lab>/shapes/<id>-stock.s.
stock() {
  local id=$1 src=$2 opt=$3
  "${CLEAN[@]}" "$CC" "$opt" -g -S "$SRC/$src" -o "$LAB/shapes/$id-stock.s" \
      2> "$LAB/shapes/$id-stock.stderr.txt" \
    || { echo "run-gcc-fixture-loop.sh: $id-stock: rc $?" >&2; failed=1; }
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
stock srcbarrier srcbarrier.c  -O2
shape clobonly   clobonly.c    handle      -O2
stock clobonly   clobonly.c    -O2
shape otherbar   otherbar.c    handle      -O2
stock otherbar   otherbar.c    -O2
shape c99inline  c99inline.c   wipe_inline -O2
shape cxxinline  cxxinline.cpp wipe_cxx    -O2
shape nobuiltin  nobuiltin.c   handle      -O2 -fno-builtin
shape nonzero    nonzero.c     handle      -O2
shape chk        chk.c         handle      -O2
shape chkconst   chkconst.c    handle      -O2

# ------------------------------------------------------------ switch
# The shapes WPIN_BARRIER_CALLS and WPIN_ZERO_COPY exist for
# (compiler/schema/wipe-pin.md sections 14.4 and 14.5). Each source is one
# function `handle` with a 32-byte stack buffer that derive() fills and use()
# reads, and whose last statement is the wipe in the form named. -O2, no -g:
# the listings of the stock, off and dry cells are compared byte for byte.

# bzero, the buffer's last use. Under the default _FORTIFY_SOURCE the target
# calls the header's gnu_inline bzero wrapper, which is not a memset when the
# pass runs (README.md, "Not counted"): bzeroCall with the switch off.
cat > "$SRC/bzero.c" <<'SHAPE_EOF'
#include <strings.h>
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  bzero(key, sizeof key);
  return 0;
}
SHAPE_EOF

# The checked memset on a local array, with a length nothing knows before the
# call: the object size is a constant, the length is not, so it cannot be
# folded into __builtin_memset before the pass (compare chkconst, which is).
cat > "$SRC/chkvar.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
int handle(unsigned long n) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  __builtin___memset_chk(key, 0, n, __builtin_object_size(key, 0));
  return 0;
}
SHAPE_EOF

# A copy from an all-zero read-only static (no initialiser, so zero), the
# buffer's last use. Compiled -U_FORTIFY_SOURCE (zcopyagg) and with the
# default _FORTIFY_SOURCE (zcopyhdr).
cat > "$SRC/zcopy.c" <<'SHAPE_EOF'
#include <string.h>
static const unsigned char vg_zeros[64];
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned n);
int handle(void) {
  unsigned char key[32];
  derive(key);
  use(key, 32);
  memcpy(key, vg_zeros, sizeof key);
  return 0;
}
SHAPE_EOF

# switchcell <id> <source> <switch-variable> [gcc flags...]
#   <id>-stock: no plugin. <id>-off, <id>-on, <id>-dry: the plugin through
#   pin-gcc.sh, target handle, with no switch, <switch-variable>=1, and that
#   and WPIN_DRY_RUN=1. Every listing is <lab>/switch/<cell>.s.
switchcell() {
  local id=$1 src=$2 var=$3
  shift 3
  "${CLEAN[@]}" "$CC" -O2 "$@" -S "$SRC/$src" -o "$LAB/switch/$id-stock.s" \
      2> "$LAB/switch/$id-stock.stderr.txt"
  local rs=$?
  kv "$LAB/switch/$id-stock.kv" "cellId=$id-stock" "source=$src" "flags=$*" "mode=stock" "rc=$rs" \
     "pluginSha256=not-loaded" "ccVersion=$CC_VERSION"
  [ $rs -eq 0 ] || { echo "run-gcc-fixture-loop.sh: $id-stock: rc $rs" >&2; failed=1; }
  echo "$id-stock"
  local mode rc envs
  for mode in off on dry; do
    envs=(WPIN_TARGET_FNS=handle)
    case "$mode" in
      on) envs+=("$var=1") ;;
      dry) envs+=("$var=1" WPIN_DRY_RUN=1) ;;
    esac
    rc=$(pinsh "$LAB/switch" "$id-$mode" "${envs[@]}" -- -O2 "$@" -S "$SRC/$src" -o "$LAB/switch/$id-$mode.s")
    kv "$LAB/switch/$id-$mode.kv" "cellId=$id-$mode" "source=$src" "flags=$*" "mode=$mode" \
       "env=${envs[*]}" "pinShRc=$rc" "pluginSha256=$PIN_SHA" "ccVersion=$CC_VERSION"
    echo "$id-$mode"
  done
  prevpair "switch-$id-off" "$SRC/$src" -O2 WPIN_TARGET_FNS=handle -- "$@"
}
switchcell bzero    bzero.c  WPIN_BARRIER_CALLS
switchcell chkvar   chkvar.c WPIN_BARRIER_CALLS
switchcell zcopyagg zcopy.c  WPIN_ZERO_COPY -U_FORTIFY_SOURCE
switchcell zcopyhdr zcopy.c  WPIN_ZERO_COPY

# ------------------------------------------------------------ buffer
# The buffer barrier (compiler/schema/wipe-pin.md section 14.6). -O2, no -g,
# target handle; every listing is <lab>/buffer/<cell>.s, the plugin cells
# through pin-gcc.sh.

# The wipe written as a loop of zero stores, the buffer's last use: not a call,
# so nothing but WPIN_BUFFER_BARRIER reaches it. The control, wipe_kept, zeroes
# its buffer the same way and then reads it; it is not in scope.
cat > "$SRC/loop.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
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
SHAPE_EOF

# An initialiser followed by uses, and no wipe. GCC lowers `= {0}` to the
# aggregate assignment `key = {}`, which is not a zero fill the barrier counts.
cat > "$SRC/init.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
void handle(void) {
  unsigned char key[32] = {0};
  derive(key);
  use(key, sizeof key);
}
SHAPE_EOF

# A buffer declared in the body of a loop and wiped by a loop of zero stores at
# the end of every iteration. The next iteration's derive() and use() name the
# same declaration, but after its clobber: another lifetime. The control is
# loop.c's.
cat > "$SRC/inloop.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
void handle(int n) {
  for (int j = 0; j < n; j++) {
    unsigned char key[32];
    derive(key);
    use(key, sizeof key);
    for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  }
}
void wipe_kept(void) {
  unsigned char buf[32];
  derive(buf);
  for (unsigned i = 0; i < sizeof buf; i++) buf[i] = 0;
  use(buf, sizeof buf);
}
SHAPE_EOF

# A loop of zero stores as an initialiser, followed by uses, and no wipe: a
# zero fill the barrier reads, every one of which a later use follows.
cat > "$SRC/initzero.c" <<'SHAPE_EOF'
void derive(unsigned char *k);
void use(const unsigned char *k, unsigned long n);
void handle(void) {
  unsigned char key[32];
  for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;
  derive(key);
  use(key, sizeof key);
}
SHAPE_EOF

# buffercell <id> <source> <modes...>: <id>-stock without the plugin, then each
# mode through pin-gcc.sh: off (no switch), on (WPIN_BUFFER_BARRIER=1), dry
# (that and WPIN_DRY_RUN=1).
buffercell() {
  local id=$1 src=$2
  shift 2
  "${CLEAN[@]}" "$CC" -O2 -S "$SRC/$src" -o "$LAB/buffer/$id-stock.s" 2> "$LAB/buffer/$id-stock.stderr.txt"
  local rs=$?
  kv "$LAB/buffer/$id-stock.kv" "cellId=$id-stock" "source=$src" "mode=stock" "rc=$rs" \
     "pluginSha256=not-loaded" "ccVersion=$CC_VERSION"
  [ $rs -eq 0 ] || { echo "run-gcc-fixture-loop.sh: $id-stock: rc $rs" >&2; failed=1; }
  echo "$id-stock"
  local mode rc envs
  for mode in "$@"; do
    envs=(WPIN_TARGET_FNS=handle)
    case "$mode" in
      on) envs+=(WPIN_BUFFER_BARRIER=1) ;;
      dry) envs+=(WPIN_BUFFER_BARRIER=1 WPIN_DRY_RUN=1) ;;
    esac
    rc=$(pinsh "$LAB/buffer" "$id-$mode" "${envs[@]}" -- -O2 -S "$SRC/$src" -o "$LAB/buffer/$id-$mode.s")
    kv "$LAB/buffer/$id-$mode.kv" "cellId=$id-$mode" "source=$src" "mode=$mode" \
       "env=${envs[*]}" "pinShRc=$rc" "pluginSha256=$PIN_SHA" "ccVersion=$CC_VERSION"
    echo "$id-$mode"
  done
}
buffercell loopbar loop.c off on dry
prevpair "buffer-loopbar-off" "$SRC/loop.c" -O2 WPIN_TARGET_FNS=handle --
buffercell initbar init.c on
buffercell inloop inloop.c on
buffercell initzero initzero.c on

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

# ------------------------------------------------------------ lto
# The trailing shape at -O2, target handle. Every step is the compiler run
# directly, each rc written down; the checker grades what they left.
#
#   lto-compile    -flto -c with the plugin: the object carries GIMPLE that
#                  holds the pin, and cc1 writes the record (copied to
#                  compile-record.json before the next step can remove it).
#   lto-linkline   that object linked -flto -shared with the plugin on the link
#                  line and the SAME WPIN_OUT, as a build that exports WPIN_* to
#                  every step would do. lto1 loads the plugin, which removes the
#                  compile's record (the stale-record rule runs before any
#                  refusal) and then refuses.
#   lto-stock      stock -flto -shared links of the pinned object and of an
#                  object compiled -flto without the plugin, and objdump -d of
#                  each: whether the zero fill survived the link-time
#                  optimisation, read from the linked code.
LTO="$LAB/lto"
LREC="$LTO/wpin-out.json"
"${CLEAN[@]}" WPIN_OUT="$LREC" WPIN_TARGET_FNS=handle \
    "$CC" -fplugin="$PLUGIN" -O2 -flto -c "$SRC/trailing.c" -o "$LTO/pinned.o" \
    2> "$LTO/compile.stderr.txt"
rc_compile=$?
rec_after_compile=absent
[ -f "$LREC" ] && rec_after_compile=file && cp "$LREC" "$LTO/compile-record.json"
"${CLEAN[@]}" "$CC" -O2 -flto -c "$SRC/trailing.c" -o "$LTO/unpinned.o" \
    2> "$LTO/unpinned.stderr.txt"
rc_unpinned=$?
kv "$LTO/lto-compile.kv" "cellId=lto-compile" "rc=$rc_compile" "unpinnedRc=$rc_unpinned" \
   "wpinOutAfter=$rec_after_compile" "pluginSha256=$PIN_SHA" "ccVersion=$CC_VERSION"
echo lto-compile

rec_before_link=absent
[ -f "$LREC" ] && rec_before_link=file
"${CLEAN[@]}" WPIN_OUT="$LREC" WPIN_TARGET_FNS=handle \
    "$CC" -fplugin="$PLUGIN" -O2 -flto -shared "$LTO/pinned.o" -o "$LTO/linkline.so" \
    2> "$LTO/linkline.stderr.txt"
rc_link=$?
rec_after_link=absent
[ -d "$LREC" ] && rec_after_link=dir
[ -f "$LREC" ] && rec_after_link=file
kv "$LTO/lto-linkline.kv" "cellId=lto-linkline" "rc=$rc_link" "wpinOutBefore=$rec_before_link" \
   "wpinOutAfter=$rec_after_link" "pluginSha256=$PIN_SHA" "ccVersion=$CC_VERSION"
echo lto-linkline

"${CLEAN[@]}" "$CC" -O2 -flto -shared "$LTO/pinned.o" -o "$LTO/stock-pinned.so" \
    2> "$LTO/stock-pinned.stderr.txt"
rc_sp=$?
"${CLEAN[@]}" "$CC" -O2 -flto -shared "$LTO/unpinned.o" -o "$LTO/stock-unpinned.so" \
    2> "$LTO/stock-unpinned.stderr.txt"
rc_su=$?
for so in linkline stock-pinned stock-unpinned; do
  if [ -f "$LTO/$so.so" ]; then
    objdump -d --no-show-raw-insn "$LTO/$so.so" > "$LTO/$so.objdump.txt" 2> /dev/null \
      || rm -f "$LTO/$so.objdump.txt"
  fi
done
kv "$LTO/lto-stock.kv" "cellId=lto-stock" "pinnedRc=$rc_sp" "unpinnedRc=$rc_su" \
   "objdump=$(objdump --version | head -n1)" "ccVersion=$CC_VERSION"
echo lto-stock

# ------------------------------------------------------------ xtu
# A wipe helper in another translation unit. Without LTO, use.c sees only
# secure_wipe's declaration, so the call stays, and the helper's memset -- on a
# length the helper does not know -- stays with it. An LTO link sees the
# helper's body and can inline it into handle, where the fill is a store to a
# local that dies right after it. The four units are written here on every run,
# never into the repository, byte for byte as the WipePin loop writes them.
XSRC="$LAB/xtu/src"

# The helper, external. The memset is on line 3, which the record carries.
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
# the pinned helper out of line, and xtu-lto-pin could not show an inlining --
# check-gcc-fixture-loop.py, the xtu expectations.) Both noinline, so that the
# function a fill ends up in is the same function in every link, whatever LTO
# does with main.
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

# xtu <id> <none|lto> <stock|pin|dry>
#   main.c, use.c  stock, -O2, plus -flto for the lto form
#   wipe.c         the same; for pin and dry with the plugin loaded,
#                  WPIN_TARGET_FNS=secure_wipe, WPIN_OUT=<cell>/wipe.record.json,
#                  and WPIN_DRY_RUN=1 for dry
#   io.c           stock, -O2, never -flto
#   link           stock: -O2, and -flto for the lto form, the executable
#                  <cell>/prog
# Written down, not judged: each step's rc, and whether the record is there.
xtu() {
  local id=$1 form=$2 mode=$3
  local d="$LAB/xtu/$id"
  rm -rf "$d"
  mkdir -p "$d"
  local lto=()
  case "$form" in
    none) ;;
    lto) lto=(-flto) ;;
    *) echo "run-gcc-fixture-loop.sh: xtu: unknown form $form" >&2; exit 3 ;;
  esac
  local rec="$d/wipe.record.json"
  local pinenv=() pinflags=()
  case "$mode" in
    stock) ;;
    pin) pinenv=(WPIN_OUT="$rec" WPIN_TARGET_FNS=secure_wipe); pinflags=(-fplugin="$PLUGIN") ;;
    dry) pinenv=(WPIN_OUT="$rec" WPIN_TARGET_FNS=secure_wipe WPIN_DRY_RUN=1); pinflags=(-fplugin="$PLUGIN") ;;
    *) echo "run-gcc-fixture-loop.sh: xtu: unknown mode $mode" >&2; exit 3 ;;
  esac
  local u rcs=()
  for u in main use; do
    "${CLEAN[@]}" "$CC" -O2 "${lto[@]+"${lto[@]}"}" -c "$XSRC/$u.c" -o "$d/$u.o" 2> "$d/$u.stderr.txt"
    rcs+=("${u}Rc=$?")
  done
  "${CLEAN[@]}" "${pinenv[@]+"${pinenv[@]}"}" \
      "$CC" "${pinflags[@]+"${pinflags[@]}"}" -O2 "${lto[@]+"${lto[@]}"}" \
      -c "$XSRC/wipe.c" -o "$d/wipe.o" 2> "$d/wipe.stderr.txt"
  rcs+=("wipeRc=$?")
  "${CLEAN[@]}" "$CC" -O2 -c "$XSRC/io.c" -o "$d/io.o" 2> "$d/io.stderr.txt"
  rcs+=("ioRc=$?")
  "${CLEAN[@]}" "$CC" -O2 "${lto[@]+"${lto[@]}"}" \
      "$d/main.o" "$d/use.o" "$d/wipe.o" "$d/io.o" -o "$d/prog" 2> "$d/link.stderr.txt"
  rcs+=("linkRc=$?")
  local recstate=not-loaded sha=not-loaded
  if [ "$mode" != stock ]; then
    recstate=absent
    [ -f "$rec" ] && recstate=file
    sha=$PIN_SHA
  fi
  kv "$LAB/xtu/$id.kv" "cellId=$id" "form=$form" "mode=$mode" "${rcs[@]}" "record=$recstate" \
     "pluginSha256=$sha" "ccVersion=$CC_VERSION"
  local r
  for r in "${rcs[@]}"; do
    [ "${r#*=}" = 0 ] || { echo "run-gcc-fixture-loop.sh: $id: $r" >&2; failed=1; }
  done
  [ -f "$d/prog" ] || { echo "run-gcc-fixture-loop.sh: $id: no executable" >&2; failed=1; }
  [ "$recstate" != absent ] || { echo "run-gcc-fixture-loop.sh: $id: the plugin wrote no record" >&2; failed=1; }
  echo "$id"
}
xtu xtu-nolto     none stock
xtu xtu-lto-stock lto  stock
xtu xtu-lto-pin   lto  pin
xtu xtu-lto-dry   lto  dry

if [ $failed -ne 0 ]; then
  echo "run-gcc-fixture-loop.sh: at least one cell did not compile" >&2
  exit 3
fi
exit 0
