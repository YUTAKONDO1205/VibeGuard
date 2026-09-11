#!/bin/bash
# One cell: compile one translation unit with WipePin loaded and leave its
# record behind. Same shape as compiler/llvm-pass/scripts/observe.sh; nothing
# here interprets the record.
#
#   pin.sh <plugin.so> <out.json> <clang args...>
#
#   WPIN_TARGET_FNS / WPIN_SCOPE / WPIN_DRY_RUN   passed through to the plugin
#   WPIN_CC                                       compiler (default clang-18)
#
# WPIN_OUT is set to <out.json> by this script. Give clang ONE source file: the
# plugin writes one record per module and a second module overwrites the first
# (the plugin says so on stderr when it happens).
#
# Next to the record it writes <out>.manifest.kv (plugin sha256, compiler, rc,
# what the plugin was asked to do) and <out>.stderr.txt (clang's stderr, which is
# also passed through). <out> is <out.json> without its .json suffix.
#
# Exit codes follow compiler/schema/interfaces.md section 7:
#   0  clang succeeded and a record was written
#   1  clang failed (its diagnostics pass through)
#   3  clang succeeded and no record was written -- the plugin refused to
#      install, or its pass never ran, or the record could not be written.
#      Never reported as 0: a build that loaded a repair plugin which did
#      nothing is indistinguishable, by rc alone, from one that was repaired.
set -u

PLUGIN=${1:?usage: pin.sh <plugin.so> <out.json> <clang args...>}
OUT=${2:?usage: pin.sh <plugin.so> <out.json> <clang args...>}
shift 2

CC=${WPIN_CC:-clang-18}
case "$OUT" in
  *.json) BASE=${OUT%.json} ;;
  *) BASE=$OUT ;;
esac
MANIFEST="$BASE.manifest.kv"
ERRFILE="$BASE.stderr.txt"

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT" "$MANIFEST" "$ERRFILE"

PLUGIN_SHA=absent
[ -f "$PLUGIN" ] && PLUGIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)
CC_VERSION=$("$CC" --version 2>/dev/null | head -n1)

# The manifest leaves the machine's home directory out; it is a lab artefact, but
# a lab artefact is one copy-paste away from a tracked file.
sanitise() { sed -e "s#$HOME#~#g"; }

# Two source files on one clang line each write WPIN_OUT and the last one wins,
# with nothing from the plugin to say so. Measured on clang 18.1.3 with
# `-c a.c b.c`: rc 0, no warning, one record naming b.c. The count below is a
# heuristic over the operands, so it warns rather than refuses.
SOURCES=0
prev=
for a in "$@"; do
  case "$prev" in
    -o|-MF|-MT|-MQ|-include|-imacros|-x|-Xclang|-mllvm) prev=; continue ;;
  esac
  prev=$a
  case "$a" in
    -*) ;;
    *.c|*.cc|*.cpp|*.cxx|*.c++|*.i|*.ii|*.m|*.mm) SOURCES=$((SOURCES + 1)) ;;
  esac
done
if [ "$SOURCES" -ne 1 ]; then
  echo "pin.sh: $SOURCES source operand(s) on this line; WipePin writes one record per source file and the last one overwrites the rest" >&2
fi

export WPIN_OUT="$OUT"
"$CC" -fpass-plugin="$PLUGIN" "$@" 2> "$ERRFILE"
rc=$?
cat "$ERRFILE" >&2

status=0
if [ $rc -ne 0 ]; then
  status=1
elif [ ! -s "$OUT" ]; then
  status=3
fi

{
  echo "pluginSha256=$PLUGIN_SHA"
  echo "plugin=$(printf '%s' "$PLUGIN" | sanitise)"
  echo "cc=$CC"
  echo "ccVersion=$CC_VERSION"
  echo "rc=$rc"
  echo "status=$status"
  echo "sourceOperands=$SOURCES"
  if [ -s "$OUT" ]; then echo "record=$(basename "$OUT")"; else echo "record="; fi
  echo "wpinTargetFns=${WPIN_TARGET_FNS-}"
  echo "wpinScope=${WPIN_SCOPE-}"
  echo "wpinDryRun=${WPIN_DRY_RUN-}"
  printf 'argvB64=%s\n' "$(printf '%s\n' "$@" | sanitise | base64 -w0)"
  printf 'stderrB64=%s\n' "$( [ -s "$ERRFILE" ] && head -c 4000 "$ERRFILE" | sanitise | base64 -w0 )"
} > "$MANIFEST"

case $status in
  1) echo "pin.sh: compiler exited $rc" >&2 ;;
  3) echo "pin.sh: the compiler succeeded and no WipePin record was written; whatever the plugin did or did not do is unaccounted for" >&2 ;;
esac
exit $status
