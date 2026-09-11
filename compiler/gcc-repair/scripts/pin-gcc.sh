#!/bin/bash
# One cell: compile one translation unit with WipePinGcc loaded and leave its
# record behind. The gcc twin of compiler/llvm-repair/scripts/pin.sh, with the
# same arguments, the same exit codes and the same manifest fields. The only
# reading of the record done here is the one the exit code needs: whether it
# says anything was repaired.
#
#   pin-gcc.sh <libWipePinGcc.so> <out.json> <gcc args...>
#
#   WPIN_TARGET_FNS / WPIN_SCOPE / WPIN_DRY_RUN   passed through to the plugin
#   WPIN_CC                                       compiler (default gcc-13)
#
# WPIN_OUT is set to <out.json> by this script. Give gcc ONE source file: the
# driver starts one cc1 per source file, each loads the plugin, each deletes
# WPIN_OUT when it loads and writes its own record at the end, and the last one
# to finish owns the file (measured: README.md, "Two source files").
#
# Next to the record it writes <out>.manifest.kv (plugin sha256, compiler, rc,
# what the plugin was asked to do, and what the record says it did) and
# <out>.stderr.txt (the compiler's stderr, which is also passed through).
# <out> is <out.json> without its .json suffix.
#
# Exit codes follow compiler/schema/interfaces.md section 7, plus 4 -- the
# same meanings as pin.sh:
#   0  the compiler succeeded, a wipe-pin-v2 record from WipePinGcc was written,
#      it pinned at least one site, and every requested name resolved. NOT "the
#      wipe survived" -- only the stock observation, re-run with the plugin, can
#      say that -- and not even "the wipe was pinned": a pinned clear-before-fill
#      memset counts too. followedByUseCount and the plugin's "partial" line are
#      where that shows.
#   1  the compiler failed (its diagnostics pass through)
#   3  the compiler succeeded and no usable record was written -- the plugin
#      refused to install, or the unit never reached the end of compilation
#      (-fsyntax-only, -E), or the record could not be written, or what was
#      written is not a wipe-pin-v2 WipePinGcc record (read strictly by
#      wpin_gcc_record.py, digests re-derived).
#   4  the compiler succeeded and a record was written, but nothing was
#      repaired: pinnedCount is 0 (a dry run, a misspelt name, nothing eligible
#      in scope) or a requested name did not resolve.
#
# Requires python3 to read the record (no jq, no node).
set -u

PLUGIN=${1:?usage: pin-gcc.sh <libWipePinGcc.so> <out.json> <gcc args...>}
OUT=${2:?usage: pin-gcc.sh <libWipePinGcc.so> <out.json> <gcc args...>}
shift 2

HERE=$(cd "$(dirname "$0")" && pwd)
READER="$HERE/wpin_gcc_record.py"
CC=${WPIN_CC:-gcc-13}
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

# The manifest leaves the machine's home directory out; it is a lab artefact,
# but a lab artefact is one copy-paste away from a tracked file.
sanitise() { sed -e "s#$HOME#~#g"; }

# Two source files on one line: two cc1 processes, two records, one path. The
# count is a heuristic over the operands, so it warns rather than refuses.
SOURCES=0
prev=
for a in "$@"; do
  case "$prev" in
    -o|-MF|-MT|-MQ|-include|-imacros|-x|-Xassembler|-Xlinker|-Xpreprocessor|-isystem|-iquote|-idirafter|-I|-D|-U|-L|-l)
      prev=; continue ;;
  esac
  prev=$a
  case "$a" in
    -*) ;;
    *.c|*.cc|*.cpp|*.cxx|*.c++|*.C|*.i|*.ii) SOURCES=$((SOURCES + 1)) ;;
  esac
done
if [ "$SOURCES" -ne 1 ]; then
  echo "pin-gcc.sh: $SOURCES source operand(s) on this line; WipePinGcc writes one record per source file and the last one overwrites the rest" >&2
fi

export WPIN_OUT="$OUT"
"$CC" -fplugin="$PLUGIN" "$@" 2> "$ERRFILE"
rc=$?
cat "$ERRFILE" >&2

status=0
REC_KV=
REC_ERR=
if [ $rc -ne 0 ]; then
  status=1
elif [ ! -s "$OUT" ]; then
  status=3
else
  if ! command -v python3 >/dev/null 2>&1; then
    REC_ERR="python3 not found; the record cannot be read"
  elif [ ! -f "$READER" ]; then
    REC_ERR="the record reader is missing"
  else
    REC_KV=$(python3 "$READER" "$OUT")
    prc=$?
    REC_ERR=$(printf '%s\n' "$REC_KV" | sed -n 's/^error=//p')
    if [ -z "$REC_ERR" ]; then
      if [ $prc -ne 0 ]; then
        REC_ERR="the record reader failed (rc $prc)"
      elif ! printf '%s\n' "$REC_KV" | grep -q '^exactAll='; then
        REC_ERR="the record reader did not finish"
      fi
    fi
  fi
  if [ -n "$REC_ERR" ]; then
    status=3
    REC_KV=
  fi
fi

field() { printf '%s\n' "$REC_KV" | sed -n "s/^$1=//p"; }
PINNED=$(field pinnedCount)
WOULD=$(field wouldPinCount)
FOLLOWED=$(field followedByUseCount)
UNRESOLVED=$(field unresolved)
EXACT_ALL=$(field exactAll)

if [ $status -eq 0 ] && { [ "$PINNED" = 0 ] || [ -n "$UNRESOLVED" ]; }; then
  status=4
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
  echo "recordError=$REC_ERR"
  echo "pinnedCount=$PINNED"
  echo "wouldPinCount=$WOULD"
  echo "followedByUseCount=$FOLLOWED"
  echo "unresolved=$UNRESOLVED"
  echo "exactAll=$EXACT_ALL"
  echo "wpinTargetFns=${WPIN_TARGET_FNS-}"
  echo "wpinScope=${WPIN_SCOPE-}"
  echo "wpinDryRun=${WPIN_DRY_RUN-}"
  printf 'argvB64=%s\n' "$(printf '%s\n' "$@" | sanitise | base64 -w0)"
  printf 'stderrB64=%s\n' "$( [ -s "$ERRFILE" ] && head -c 4000 "$ERRFILE" | sanitise | base64 -w0 )"
} > "$MANIFEST"

case $status in
  1) echo "pin-gcc.sh: compiler exited $rc" >&2 ;;
  3)
    if [ -n "$REC_ERR" ]; then
      echo "pin-gcc.sh: the compiler succeeded and the WipePinGcc record is not usable ($REC_ERR); whatever the plugin did or did not do is unaccounted for" >&2
    else
      echo "pin-gcc.sh: the compiler succeeded and no WipePinGcc record was written; whatever the plugin did or did not do is unaccounted for" >&2
    fi ;;
  4)
    why=
    [ "$PINNED" = 0 ] && why="pinnedCount 0 (wouldPinCount $WOULD)"
    if [ -n "$UNRESOLVED" ]; then
      [ -n "$why" ] && why="$why; "
      why="${why}not resolved: $UNRESOLVED"
    fi
    echo "pin-gcc.sh: a WipePinGcc record was written and nothing was repaired: $why" >&2 ;;
esac
exit $status
