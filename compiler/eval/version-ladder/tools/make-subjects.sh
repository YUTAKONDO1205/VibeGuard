#!/bin/bash
# Put this lane's measurement inputs in the lab, on the side that produces them.
#
#   bash compiler/eval/version-ladder/tools/make-subjects.sh
#   VG_LAB=/somewhere bash compiler/eval/version-ladder/tools/make-subjects.sh
#
# There are two kinds of subject and only one of them needs generating.
#
#   corpus subjects   the r2 files, which are tracked at
#                     compiler/eval/ai-generated/generated-corpus/r2/. The runner
#                     reads them from the tree and writes its own ablated copies
#                     into --out; nothing to do here.
#   the fixture       the hand-written erasure fixture. It is NOT written here.
#                     compiler/llvm-pass/tools/make-fixtures.sh is the one
#                     definition of those bytes and this script calls it. A copy
#                     of a fixture is how two lanes quietly stop measuring the
#                     same subject, and the fixture's own header says why it is
#                     generated rather than committed: a fixture under compiler/
#                     is a measurement input in the published tree, which
#                     scripts/check-packaging-invariants.mjs refuses.
#
# After this, the fixture's target.c is at $VG_LAB/version-ladder/fixtures/erasure,
# which is what the runner's --fixture wants.
set -eu

LAB=${VG_LAB:-$HOME/vg-lab}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../../.." && pwd)

DEST="$LAB/version-ladder"
mkdir -p "$DEST"

# make-fixtures.sh writes to $IRCK_LAB/fixtures; point it at this lane's dir so
# the two lanes do not share a scratch directory. (The repair loop's README
# already records what sharing one costs: "Do not run two instances at once".)
IRCK_LAB="$DEST" bash "$REPO/compiler/llvm-pass/tools/make-fixtures.sh"

echo "fixture:  $DEST/fixtures/erasure/target.c"
echo "run it:   node compiler/eval/version-ladder/run-version-ladder.mjs --out $DEST/out --fixture $DEST/fixtures/erasure"
