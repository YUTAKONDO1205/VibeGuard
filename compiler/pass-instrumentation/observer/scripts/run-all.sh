#!/usr/bin/env bash
# Clean rebuild plus every measurement, in order. Exit 0 only if all five pass.
#
#   bash compiler/pass-instrumentation/observer/scripts/run-all.sh
#   OBS_LAB=/somewhere bash .../run-all.sh
#
# Sources are here and tracked; the build tree, the fixtures and the results are
# on the Linux filesystem and are not. That split is the rule this directory is
# under, and it is also why the fixtures are generated: whatever is in
# tools/make-fixtures.sh is what was measured.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
LAB=${OBS_LAB:-$HOME/vg-lab/pass-observer}
export OBS_LAB="$LAB"
mkdir -p "$LAB"
RL="$LAB/rl.sh"
cat > "$RL" <<'RUNLOG_EOF'
#!/bin/sh
# Every command this measurement runs, with its exit code, in one file. The
# report is the claim; this is what the claim can be checked against.
printf '%s
' "$*" >> "$OBS_LAB/run-log.txt"
"$@"
rc=$?
printf '  exit=%s
' "$rc" >> "$OBS_LAB/run-log.txt"
exit $rc
RUNLOG_EOF
chmod +x "$RL"

bash "$ROOT/tools/make-fixtures.sh" >/dev/null || exit 3

rm -rf "$HOME/vg-build/pass-observer" "$HOME/vg-build/pass-observer-rq2"
$RL bash -c "cmake -S '$ROOT' -B \$HOME/vg-build/pass-observer -G Ninja -DLLVM_DIR=\$(llvm-config-18 --cmakedir) -DCMAKE_BUILD_TYPE=Release >/dev/null && ninja -C \$HOME/vg-build/pass-observer" || exit 3
$RL bash -c "cmake -S '$ROOT/rq2' -B \$HOME/vg-build/pass-observer-rq2 -G Ninja -DLLVM_DIR=\$(llvm-config-18 --cmakedir) -DCMAKE_BUILD_TYPE=Release >/dev/null && ninja -C \$HOME/vg-build/pass-observer-rq2" || exit 3

# ---- spike/recovery gate, on the plugin just built, before the five harnesses -
#
# The five harnesses below share one instrument and none of them can check it.
# The failure that matters is the third silent one: a subject name that resolves
# to nothing gives rc 0, an empty stderr, a non-empty log, a control reading
# PRESENT, and only the subject's own SUMMARY row missing -- indistinguishable at
# a glance from a property that was never there. tools/check-subject-resolution.mjs
# has exited 2 on exactly that since 2026-08-17, and ../README.md's own warning
# says nothing in this repository has ever called it automatically. This is the
# automatic caller.
#
# It is NOT the naive glob that warning rules out, and the difference is the whole
# reason this is safe to add here. It does not read the logs the five harnesses
# write: those are several configurations under one tree, a per-run aggregate over
# them reports `inconsistent-name` CORRECTLY, and turning a green harness red for
# that would be a defect in the wiring rather than in the instrument. What it does
# instead is compile two translation units of its OWN -- one whose wipe the
# optimiser is permitted to delete, one whose it is not, both registered in advance
# in compiler/eval/spike/claims/spike-expected.json -- into a lab of its own under
# $LAB/spike, run check-subject-resolution.mjs on each of THOSE logs, and then do
# the whole thing again with the subject name deliberately misspelt, which it must
# refuse.
#
# So what a green line here establishes is narrow and worth stating exactly:
# libPropertyObserver.so as built in THIS run, together with that checker, reads a
# known elimination, reads a known survival, and goes red when the subject name is
# wrong. It says nothing about the five harnesses' own logs, and it must not be
# described as saying anything about them.
#
# One configuration, and -O2 on purpose. The observer channel is registered at -O2
# and at no other level; at -O0 both spikes are registered to read the same word,
# so a -O0 run scores 2/2 for an instrument that could only ever report that word.
# The gate refuses such a run by itself, under NO_DISCRIMINATING_CONFIGURATION.
#
# The exit code passes through UNCHANGED (compiler/schema/interfaces.md section 7):
# 2 the gate is red, 3 a requested compiler is not installed on this host, 4 the
# registered expectations are malformed or the lab would be inside the repository.
# It is deliberately not folded into this script's own rc=2: "a harness found
# something" and "the instrument was shown not to be reading" send a reader to two
# different places, and section 7 spends 2 and 3 on that distinction.
COMPILER=$(cd "$ROOT/../.." && pwd)
SPIKE_LAB=${OBS_SPIKE_LAB:-$LAB/spike}
OBS_PLUGIN_SO=${OBS_PLUGIN:-$HOME/vg-build/pass-observer/libPropertyObserver.so}
echo "======== spike/recovery gate (observer channel, -O2)"
$RL node "$COMPILER/eval/spike/run-spike.mjs" --out "$SPIKE_LAB" --cc clang-18 --opt -O2 --observer "$OBS_PLUGIN_SO" --observer-cc clang-18 --observer-opt -O2
s=$?
echo "   exit=$s"
if [ "$s" -ne 0 ]; then
  echo "run-all.sh: STOPPED at: the spike/recovery gate (exit $s)" >&2
  echo "run-all.sh: no harness was run, so nothing below this line measured anything" >&2
  echo "run-all.sh: and no reading this run could have produced would be evidence" >&2
  echo "run-all.sh: about the observer -- the instrument itself did not come back." >&2
  exit "$s"
fi

rc=0
for h in "$ROOT/rq2/rq2.mjs" "$HERE/noninvasive.mjs" "$ROOT/rq2/modes.mjs"          "$ROOT/rq2/broken-controls.mjs" "$HERE/crosscheck.mjs"; do
  echo "======== $(basename "$h")"
  $RL node "$h" | tail -3
  s=${PIPESTATUS[0]}
  echo "   exit=$s"
  [ "$s" -ne 0 ] && rc=2
done
echo "ALL DONE rc=$rc"
exit $rc
