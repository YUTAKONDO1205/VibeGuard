#!/bin/bash
# The two proofs of concept, run against a real toolchain.
#
#   1. an unapproved object linked in is detected
#   2. a post-link modification of the artefact is detected
#
# plus the refusal the whole design rests on:
#
#   3. a map supplied from outside the wrapper is refused
#
# Each has BOTH directions. A detector with only a positive fixture is a false
# positive factory: it cannot distinguish "caught the bad thing" from "fires on
# everything", and the second is indistinguishable from the first until the day
# a clean build is blocked.
#
#   VG_LINK_LAB=<dir> bash tools/poc.sh
#
# COUNTING. Prints `inputs=N checked=N skipped=S` and exits non-zero when N is
# 0 unless --allow-empty is passed. There are no cases to skip here: every case
# needs the toolchain, and a missing toolchain fails the run rather than
# emptying it.
set -u

LAB=${VG_LINK_LAB:-$HOME/vg-lab/link-integrity}/poc
HERE=$(cd "$(dirname "$0")" && pwd)
CLI=$HERE/../vg-link.mjs
CC=${CC:-clang-18}
ALLOW_EMPTY=0
[ "${1:-}" = "--allow-empty" ] && ALLOW_EMPTY=1

for tool in "$CC" node; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool not found; this run fails rather than skipping" >&2; exit 1; }
done

rm -rf "$LAB"; mkdir -p "$LAB/records"; cd "$LAB" || exit 1

cat > main.c <<'EOF'
#include <string.h>
extern int helper(int);
extern void opaque(char *p);
volatile int sink;
/* CONTROL — the zeroing survives -O2 because the buffer escapes. */
int control_fn(int n) { char b[16]; memset(b, 0, sizeof b); opaque(b); return n; }
__attribute__((constructor)) static void ctor_main(void) { sink = 1; }
int main(void) { return helper(control_fn(3)); }
EOF
cat > helper.c <<'EOF'
volatile int hsink;
void opaque(char *p) { hsink = p[0]; }
int helper(int x) { return x * 2; }
EOF
cat > rogue.c <<'EOF'
volatile int rogue_sink;
__attribute__((constructor)) static void ctor_rogue(void) { rogue_sink = 1; }
int rogue_fn(int x) { return x + 1; }
EOF

cat > policy.json <<'EOF'
{
  "policyVersion": "policy-v0",
  "failOn": "high",
  "link": {
    "allowedObjects": ["main.o", "helper.o", "system:**/*.o"],
    "allowedLibraries": ["system:**/*.so*"],
    "allowedLinkers": ["lld"],
    "forbidLinkerScripts": true
  }
}
EOF

set -e
for u in main helper rogue; do "$CC" -c -O2 "$u.c" -o "$u.o"; done
set +e

INPUTS=0; CHECKED=0; SKIPPED=0; FAILED=0

case_() { # name, expected-exit, expected-substring-or-"", command...
  local name=$1 want=$2 needle=$3; shift 3
  INPUTS=$((INPUTS + 1))
  local out rc
  out=$("$@" 2>&1); rc=$?
  CHECKED=$((CHECKED + 1))
  local ok=1
  [ "$rc" = "$want" ] || ok=0
  if [ -n "$needle" ]; then echo "$out" | grep -q -- "$needle" || ok=0; fi
  if [ "$ok" = 1 ]; then
    printf 'ok    %-58s exit=%s\n' "$name" "$rc"
  else
    FAILED=$((FAILED + 1))
    printf 'FAIL  %-58s exit=%s want=%s needle=%s\n' "$name" "$rc" "$want" "${needle:-none}"
    echo "$out" | sed 's/^/        /'
  fi
}

echo "== PoC 1: an unapproved object linked in =="
# NEGATIVE first. If the approved link is not clean, nothing the positive case
# reports can be attributed to rogue.o.
case_ "1a NEGATIVE approved link is clean" 0 "inputs=" \
  node "$CLI" link --policy policy.json --root "$LAB" --record records/neg.json -- \
  "$CC" -fuse-ld=lld main.o helper.o -o neg.bin

case_ "1b POSITIVE rogue.o is caught (VG-LINK-001)" 2 "VG-LINK-001" \
  node "$CLI" link --policy policy.json --root "$LAB" --record "$LAB/pos.json" -- \
  "$CC" -fuse-ld=lld main.o helper.o rogue.o -o pos.bin

case_ "1c POSITIVE rogue.o reaches .init_array (VG-LINK-009)" 2 "VG-LINK-009" \
  node "$CLI" link --policy policy.json --root "$LAB" --record "$LAB/pos2.json" -- \
  "$CC" -fuse-ld=lld main.o helper.o rogue.o -o pos2.bin

# CONTROL: the approved objects must still be approved in the positive run. If
# main.o is flagged there, the run says nothing about rogue.o.
INPUTS=$((INPUTS + 1)); CHECKED=$((CHECKED + 1))
if node -e '
  const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  const d = r.verdict.decisions.find((x) => x.ref === "main.o");
  if (!d || d.allowed !== true) { console.error("control moved:", JSON.stringify(d)); process.exit(1); }
  const rogue = r.verdict.decisions.find((x) => x.ref === "rogue.o");
  if (!rogue || rogue.allowed !== false) { console.error("rogue.o not judged:", JSON.stringify(rogue)); process.exit(1); }
' "$LAB/pos.json"; then
  printf 'ok    %-58s\n' "1d CONTROL main.o still approved while rogue.o is not"
else
  FAILED=$((FAILED + 1)); printf 'FAIL  %-58s\n' "1d CONTROL main.o still approved while rogue.o is not"
fi

echo
echo "== PoC 2: a post-link modification of the artefact =="
case_ "2a NEGATIVE untouched artefact is not reported" 0 "inputs=1 checked=1" \
  node "$CLI" recheck records --root "$LAB"

printf '\0' >> neg.bin

case_ "2b POSITIVE one appended byte is caught (VG-LINK-006)" 2 "VG-LINK-006" \
  node "$CLI" recheck records --root "$LAB"

echo
echo "== PoC 3: an externally supplied map is refused =="
"$CC" -fuse-ld=lld -Wl,-Map=theirs.map main.o helper.o -o theirs.bin 2>/dev/null
case_ "3a POSITIVE a caller-named map is refused (VG-LINK-007)" 4 "VG-LINK-007" \
  node "$CLI" link --policy policy.json --root "$LAB" -- \
  "$CC" -fuse-ld=lld main.o helper.o -Wl,-Map=theirs.map -o never.bin

case_ "3b POSITIVE --map is not a flag this wrapper has" 4 "unknown option --map" \
  node "$CLI" link --policy policy.json --root "$LAB" --map theirs.map -- \
  "$CC" -fuse-ld=lld main.o helper.o -o never2.bin

INPUTS=$((INPUTS + 1)); CHECKED=$((CHECKED + 1))
if [ -f never.bin ] || [ -f never2.bin ]; then
  FAILED=$((FAILED + 1)); printf 'FAIL  %-58s\n' "3c the refused link must not have run"
else
  printf 'ok    %-58s\n' "3c the refused link never ran"
fi

echo
echo "== empty-scan guard =="
mkdir -p empty
case_ "4  an empty record directory is exit 3, never exit 0" 3 "inputs=0 checked=0 skipped=0" \
  node "$CLI" recheck empty --root "$LAB"

echo
echo "inputs=$INPUTS checked=$CHECKED skipped=$SKIPPED"
if [ "$INPUTS" -eq 0 ] && [ "$ALLOW_EMPTY" -eq 0 ]; then
  echo "inputs=0 and --allow-empty was not passed: nothing ran, so nothing is being reported clean" >&2
  exit 3
fi
if [ "$FAILED" -gt 0 ]; then echo "$FAILED case(s) failed"; exit 1; fi
echo "all $CHECKED case(s) held"
