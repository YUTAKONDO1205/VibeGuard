#!/bin/bash
# Materialise the two spikes, in both forms, into the lab -- for reading and for
# reproducing a cell by hand.
#
#   bash compiler/eval/spike/tools/make-spike-lab.sh [lab dir]
#
# The gate does NOT use this script: run-spike.mjs writes the same four files
# itself, from the same two subjects and the same appended control, because a
# gate whose inputs came from a second generator would be gating something it did
# not assemble. This exists so that a person can look at exactly what was
# compiled, and re-run one cell with nothing but a compiler and diff.
#
# Sources go to the lab, never under compiler/: measurement inputs in the
# published tree are what scripts/check-packaging-invariants.mjs refuses, and
# interfaces.md section 1 says where they live instead.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
LANE=$(cd "$HERE/.." && pwd)
LAB=${1:-${SPIKE_LAB:-$HOME/vg-lab/spike}}

mkdir -p "$LAB" || exit 3

# The positive control is appended from the shared cell module rather than copied
# here. compiler/schema/effect-symbol-lists.test.mjs fails on a new wipe-symbol
# literal, and a control pasted into this file would drift from the one every
# other lane compiles.
node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const cell = await import('file://$LANE/../ai-generated/lib/ablation-cell.mjs');
const lane = '$LANE', lab = '$LAB';
for (const [spike, file, fn] of [
  ['disappearing', 'spike-disappearing.c', 'vgspike_disappearing'],
  ['surviving', 'spike-surviving.c', 'vgspike_surviving'],
]) {
  const src = readFileSync(join(lane, 'subjects', file), 'utf8') + cell.CONTROL;
  const { spans } = cell.wipeSpans(src, fn);
  writeFileSync(join(lab, spike + '.w.c'), src, 'utf8');
  writeFileSync(join(lab, spike + '.wo.c'), cell.ablateSpans(src, spans), 'utf8');
  process.stderr.write(spike + ': ' + spans.length + ' wipe span(s), target ' + fn + '\n');
}
" || exit 3

cat <<'USAGE'
wrote to the lab:
  disappearing.w.c  disappearing.wo.c  surviving.w.c  surviving.wo.c

ONE CELL BY HAND. The criterion is the TARGET FUNCTION's body with the
assembler's own directives removed -- not a diff of the two listings. A whole-file
diff gets this wrong, and it gets it wrong in the direction that matters: at
clang-18 -O2 the only line that differs between disappearing.w.s and
disappearing.wo.s is `.file "disappearing.w.c"`, so `diff` reports a difference
and a reader concludes the wipe SURVIVED when it was eliminated (measured
2026-09-12). bodyOf() drops .file/.loc/.cfi_/.ident/.section/.p2align/.type/
.size/.globl/.align for exactly this reason; the awk below is that filter, and it
agrees with the harness on all eight of (disappearing, surviving) x
(clang-18, gcc-13) x (-O0, -O2).

  cd "$LAB"
  body() {
    awk -v fn="$2" '
      $0 ~ "^"fn":"                                  { inb = 1; next }
      inb && $0 ~ "^[ 	]*[.]size[ 	]+"fn","       { inb = 0 }
      inb {
        sub(/#.*$/, ""); sub(/[ 	]+$/, "")
        if ($0 ~ /^[ 	]*$/) next
        if ($0 ~ /^[ 	]*[.](file|loc|cfi_|ident|section|p2align|type|size|globl|align)/) next
        print
      }' "$1"
  }
  for pair in "disappearing vgspike_disappearing" "surviving vgspike_surviving"; do
    set -- $pair
    for form in w wo; do
      clang-18 -S -std=gnu11 -w -fcf-protection=none -O2 -o "$1.$form.s" "$1.$form.c"
    done
    body "$1.w.s" "$2" > "$1.w.body"; body "$1.wo.s" "$2" > "$1.wo.body"
    if diff -q "$1.w.body" "$1.wo.body" >/dev/null
      then echo "$1: bodies identical -> WIPE_ELIMINATED"
      else echo "$1: bodies differ    -> WIPE_SURVIVED"
    fi
  done

vgctl_control is in every listing. If its wipe is not visible there, the listing
says nothing about the subject either: that is the difference between "the
defence was removed" and "the detector stopped working".
USAGE
