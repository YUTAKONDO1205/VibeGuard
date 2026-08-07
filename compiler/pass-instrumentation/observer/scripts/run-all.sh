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
