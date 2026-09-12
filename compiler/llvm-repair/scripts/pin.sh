#!/bin/bash
# One cell: compile one translation unit with WipePin loaded and leave its
# record behind. Same shape as compiler/llvm-pass/scripts/observe.sh. The only
# reading of the record done here is the one the exit code needs: whether it
# says anything was repaired.
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
# what the plugin was asked to do, and what the record says it did) and
# <out>.stderr.txt (clang's stderr, which is also passed through). <out> is
# <out.json> without its .json suffix.
#
# Exit codes follow compiler/schema/interfaces.md section 7, plus 4:
#   0  clang succeeded, a wipe-pin-v2 record was written, it pinned at least one
#      site, and every requested name resolved. This is NOT "the wipe survived"
#      -- only the stock observation, re-run with the plugin, can say that -- and
#      not even "the wipe was pinned": a pinned `= {0}` initialiser counts too.
#      The manifest's followedByUseCount, and the plugin's "partial" line on
#      stderr, are where that shows.
#   1  clang failed (its diagnostics pass through)
#   3  clang succeeded and no usable record was written -- the plugin refused to
#      install, or its pass never ran (-Xclang -disable-llvm-passes), or the
#      record could not be written, or what was written is not a wipe-pin-v2
#      record python3 can read. Never reported as 0: a build that loaded a
#      repair plugin which did nothing is indistinguishable, by rc alone, from
#      one that was repaired.
#   4  clang succeeded and a record was written, but nothing was repaired: its
#      pinnedCount is 0 (a dry run, a misspelt name, nothing eligible in scope)
#      or a requested name did not resolve. A record alone is not a repair.
#
# Requires python3 to read the record (no jq).
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

# What the record says it did, as key=value lines. Anything that is not a
# well-formed wipe-pin-v2 record makes this print one `error=` line instead.
read_record() {
  python3 - "$1" <<'PY'
import json, sys

def fail(why):
    print("error=" + why)
    sys.exit(0)

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        rec = json.load(f)
except (OSError, ValueError) as e:
    fail("unreadable: %s" % type(e).__name__)
if not isinstance(rec, dict):
    fail("not an object")
if rec.get("schemaVersion") != "wipe-pin-v2":
    fail("schemaVersion %r is not wipe-pin-v2" % (rec.get("schemaVersion"),))

def count(key):
    v = rec.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        fail("%s is not a non-negative integer" % key)
    return v

pinned_count = count("pinnedCount")
would_pin = count("wouldPinCount")
sites = rec.get("pinned")
res = rec.get("resolution")
if not isinstance(sites, list) or not isinstance(res, list):
    fail("pinned or resolution is not a list")
followed = 0
for s in sites:
    if not isinstance(s, dict) or s.get("followedByUse") not in (True, False, None):
        fail("a pinned[] entry has no followedByUse")
    if s.get("followedByUse") is True:
        followed += 1
unresolved, exact_all = [], True
for r in res:
    if not isinstance(r, dict) or not isinstance(r.get("name"), str):
        fail("a resolution[] entry has no name")
    if r.get("resolution") != "resolved":
        unresolved.append(r["name"])
    elif r.get("exact") is not True:
        exact_all = False
print("pinnedCount=%d" % pinned_count)
print("wouldPinCount=%d" % would_pin)
print("followedByUseCount=%d" % followed)
print("unresolved=" + ",".join(unresolved))
print("exactAll=" + ("true" if exact_all else "false"))
PY
}

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
  else
    REC_KV=$(read_record "$OUT")
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
  1) echo "pin.sh: compiler exited $rc" >&2 ;;
  3)
    if [ -n "$REC_ERR" ]; then
      echo "pin.sh: the compiler succeeded and the WipePin record is not usable ($REC_ERR); whatever the plugin did or did not do is unaccounted for" >&2
    else
      echo "pin.sh: the compiler succeeded and no WipePin record was written; whatever the plugin did or did not do is unaccounted for" >&2
    fi ;;
  4)
    why=
    [ "$PINNED" = 0 ] && why="pinnedCount 0 (wouldPinCount $WOULD)"
    if [ -n "$UNRESOLVED" ]; then
      [ -n "$why" ] && why="$why; "
      why="${why}not resolved: $UNRESOLVED"
    fi
    echo "pin.sh: a WipePin record was written and nothing was repaired: $why" >&2 ;;
esac
exit $status
