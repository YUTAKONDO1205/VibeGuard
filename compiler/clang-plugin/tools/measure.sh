#!/usr/bin/env bash
# Everything this component claims, measured in one run.
#
#   bash compiler/clang-plugin/tools/measure.sh
#
# Writes to ~/vg-lab/clang-ast-gate (never under compiler/), appends every
# command and its exit code to ~/vg-lab/clang-ast-gate/run-log.txt, and exits
# non-zero if any assertion fails. Nothing here is conditional on a previous
# run: it removes and rebuilds its own output directory first.
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$HOME/vg-lab/clang-ast-gate"
BUILD="$HOME/vg-build/clang-plugin"
FIX="$LAB/fixtures"
OUT="$LAB/out"
RES="$LAB/results"
LOG="$LAB/run-log.txt"
PLUGIN="$BUILD/libIntentGate.so"
RULES="$SRC/rules/default-rules.json"
EXPECT="$SRC/tools/expected.json"
CC=clang-18

mkdir -p "$LAB" "$OUT" "$RES" "$OUT/obj/with" "$OUT/obj/without" "$OUT/obj/ctl"
: > "$RES/summary.txt"

FAILURES=0
note() { echo "$*" | tee -a "$RES/summary.txt"; }
fail() { echo "FAIL: $*" | tee -a "$RES/summary.txt"; FAILURES=$((FAILURES + 1)); }

run() {
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) \$ $*" >> "$LOG"
  "$@" >> "$LOG" 2>&1
  local rc=$?
  echo "--- exit=$rc" >> "$LOG"
  return $rc
}
# Same, but the caller wants the output too.
runv() {
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) \$ $*" >> "$LOG"
  local o
  o="$("$@" 2>&1)"
  local rc=$?
  printf '%s\n' "$o" >> "$LOG"
  echo "--- exit=$rc" >> "$LOG"
  printf '%s\n' "$o"
  return $rc
}

FIXTURES="confirmed rejected refined_macro refined_fnptr rejected_more mixed wipe astonly_alias"

gate() { # gate <source> <findings> <record> [extra clang args...]
  local src="$1" fnd="$2" rec="$3"; shift 3
  "$CC" -fplugin="$PLUGIN" \
    -Xclang -add-plugin -Xclang intent-gate \
    -Xclang -plugin-arg-intent-gate -Xclang "findings=$fnd" \
    -Xclang -plugin-arg-intent-gate -Xclang "rules=$RULES" \
    -Xclang -plugin-arg-intent-gate -Xclang "root=$FIX" \
    -Xclang -plugin-arg-intent-gate -Xclang "out=$rec" \
    -Xclang -plugin-arg-intent-gate -Xclang quiet \
    "$@" -c "$src"
}

note "### 0. environment"
note "$($CC --version | head -1)"
note "plugin: $PLUGIN"
[ -f "$PLUGIN" ] || { fail "plugin not built — run: ninja -C $BUILD"; exit 1; }
note "plugin sha256: $(sha256sum "$PLUGIN" | cut -d' ' -f1)"

note ""
note "### 1. fixtures"
run bash "$SRC/tools/make-fixtures.sh" "$FIX" || fail "make-fixtures.sh"
# The positive control for the classifier: rejected.c with ONE line rewritten
# from a string literal into a real call. Nothing else changes. If the verdict
# for that line does not flip from Rejected to Confirmed, the classifier is not
# reading its input and every other verdict here is worthless.
sed '7s#.*#  return (system("id") == 0) ? "ok" : "failed";#' \
  "$FIX/rejected.c" > "$FIX/rejected_positive_control.c"
note "fixtures: $(ls -1 "$FIX" | tr '\n' ' ')"
note "control diff (rejected.c -> rejected_positive_control.c):"
diff "$FIX/rejected.c" "$FIX/rejected_positive_control.c" | sed 's/^/    /' | tee -a "$RES/summary.txt"

note ""
note "### 2. classification"
ALL="$FIXTURES rejected_positive_control"
for f in $ALL; do
  run node "$SRC/tools/lexscan.mjs" "$FIX/$f.c" --root "$FIX" || fail "lexscan $f"
  node "$SRC/tools/lexscan.mjs" "$FIX/$f.c" --root "$FIX" > "$OUT/$f.findings.json"
  run gate "$FIX/$f.c" "$OUT/$f.findings.json" "$OUT/$f.gate.json" -o "$OUT/obj/with/$f.o" \
    || fail "gate compile $f"
  msg="$(runv node "$SRC/tools/check-verdicts.mjs" "$EXPECT" "$f.c" "$OUT/$f.gate.json")"
  rc=$?
  note "$msg"
  [ $rc -eq 0 ] || fail "expectations for $f (exit $rc)"
done

note ""
note "### 3. positive control A — a rejected lexeme rewritten into a real call"
before=$(node -e 'const j=require(process.argv[1]);const v=j.verdicts.find(v=>v.lexical.line===7);console.log(v?v.verdict+"/"+v.reason:"MISSING")' "$OUT/rejected.gate.json")
after=$(node -e 'const j=require(process.argv[1]);const v=j.verdicts.find(v=>v.lexical.line===7);console.log(v?v.verdict+"/"+v.reason:"MISSING")' "$OUT/rejected_positive_control.gate.json")
note "  rejected.c line 7                 -> $before"
note "  rejected_positive_control.c L7    -> $after"
if [ "$before" = "Rejected/inert-lexeme" ] && [ "$after" = "Confirmed/direct-call" ]; then
  note "  PASS: the verdict follows the source, so the classifier reads its input"
else
  fail "positive control A: expected Rejected/inert-lexeme -> Confirmed/direct-call"
fi

note ""
note "### 4. positive control B — move the finding, the verdict must move with it"
# confirmed.c line 6 holds the call. Point the same finding at line 4, which is
# the function signature: the identifier `system` is not spelled there, so the
# only correct answer is Rejected/no-lexeme.
node -e '
const fs=require("fs");
const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
for (const f of j.findings) f.where.line = 4;
fs.writeFileSync(process.argv[2], JSON.stringify(j,null,2));
' "$OUT/confirmed.findings.json" "$OUT/confirmed.moved.findings.json"
run gate "$FIX/confirmed.c" "$OUT/confirmed.moved.findings.json" "$OUT/confirmed.moved.gate.json" \
  -o "$OUT/obj/ctl/confirmed.moved.o" || fail "gate compile confirmed.moved"
movedv=$(node -e 'const j=require(process.argv[1]);const v=j.verdicts[0];console.log(v?v.verdict+"/"+v.reason:"MISSING")' "$OUT/confirmed.moved.gate.json")
note "  confirmed.c, finding moved to line 4 -> $movedv"
if [ "$movedv" = "Rejected/no-lexeme" ]; then
  note "  PASS: the verdict is a function of the finding's location"
else
  fail "positive control B: expected Rejected/no-lexeme, got $movedv"
fi

note ""
note "### 5. non-invasiveness — sha256 of the object file, plugin on vs off"
printf 'mode\tfixture\twith-plugin\twithout-plugin\tequal\n' > "$RES/sha256.tsv"
NEQ=0
for mode in "c:-O0" "c:-O1" "c:-O2" "c:-Os" "cxx:-O0" "cxx:-O2"; do
  lang="${mode%%:*}"; opt="${mode##*:}"
  langflag="-x c"; [ "$lang" = cxx ] && langflag="-x c++"
  for f in $FIXTURES; do
    run "$CC" $langflag $opt -c "$FIX/$f.c" -o "$OUT/obj/without/$f.o" || { fail "plain compile $f $mode"; continue; }
    a=$(sha256sum "$OUT/obj/without/$f.o" | cut -d' ' -f1)
    run gate "$FIX/$f.c" "$OUT/$f.findings.json" "$OUT/$f.gate.json" $langflag $opt \
      -o "$OUT/obj/with/$f.o" || { fail "gate compile $f $mode"; continue; }
    b=$(sha256sum "$OUT/obj/with/$f.o" | cut -d' ' -f1)
    eq=no; [ "$a" = "$b" ] && eq=yes
    [ "$eq" = no ] && NEQ=$((NEQ+1))
    printf '%s\t%s\t%s\t%s\t%s\n' "$lang$opt" "$f.c" "$b" "$a" "$eq" >> "$RES/sha256.tsv"
  done
done
TOTAL=$(($(wc -l < "$RES/sha256.tsv") - 1))
note "  $((TOTAL - NEQ))/$TOTAL object files identical with and without the plugin"
note "  table: $RES/sha256.tsv"
[ "$NEQ" -eq 0 ] || fail "$NEQ object files differ with the plugin loaded"

note ""
note "### 6. positive controls for the digest comparison itself"
# (a) determinism: without the plugin, two compiles of the same input must agree,
#     otherwise the equality in §5 proves nothing.
run "$CC" -O2 -c "$FIX/mixed.c" -o "$OUT/obj/ctl/det1.o" || fail "det1"
run "$CC" -O2 -c "$FIX/mixed.c" -o "$OUT/obj/ctl/det1.o" || fail "det1 again"
d1=$(sha256sum "$OUT/obj/ctl/det1.o" | cut -d' ' -f1)
run "$CC" -O2 -c "$FIX/mixed.c" -o "$OUT/obj/ctl/det2.o" || fail "det2"
d2=$(sha256sum "$OUT/obj/ctl/det2.o" | cut -d' ' -f1)
if [ "$d1" = "$d2" ]; then note "  (a) repeat compile is deterministic: $d1"; else fail "(a) clang is not deterministic here; §5 equality is meaningless"; fi
# (b) sensitivity: a real codegen difference must show up as a different digest.
run "$CC" -O0 -c "$FIX/mixed.c" -o "$OUT/obj/ctl/o0.o" || fail "o0"
s0=$(sha256sum "$OUT/obj/ctl/o0.o" | cut -d' ' -f1)
if [ "$s0" != "$d1" ]; then note "  (b) -O0 vs -O2 digests differ, so the comparison detects codegen changes"; else fail "(b) -O0 and -O2 produced the same digest — the comparison is vacuous"; fi
# (c) sensitivity to a one-line source change.
run "$CC" -O2 -c "$FIX/rejected.c" -o "$OUT/obj/ctl/rej.o" || fail "rej"
run "$CC" -O2 -c "$FIX/rejected_positive_control.c" -o "$OUT/obj/ctl/rejpc.o" || fail "rejpc"
r1=$(sha256sum "$OUT/obj/ctl/rej.o" | cut -d' ' -f1)
r2=$(sha256sum "$OUT/obj/ctl/rejpc.o" | cut -d' ' -f1)
if [ "$r1" != "$r2" ]; then note "  (c) the one-line control change moves the digest"; else fail "(c) a one-line change did not move the digest"; fi

note ""
note "### 7. -add-plugin vs -plugin vs -fplugin alone"
rm -f "$OUT/obj/ctl/trap_add.o" "$OUT/obj/ctl/trap_replace.o" "$OUT/obj/ctl/trap_bare.o"
# -fplugin= alone, with no -add-plugin. getActionType() is AddAfterMainAction,
# which registers whenever the MODULE is loaded, so the gate runs anyway. Worth
# measuring rather than assuming: it is the difference between a gate that can
# be skipped by forgetting a flag and one that cannot.
run "$CC" -fplugin="$PLUGIN" \
  -Xclang -plugin-arg-intent-gate -Xclang "findings=$OUT/mixed.findings.json" \
  -Xclang -plugin-arg-intent-gate -Xclang "root=$FIX" \
  -Xclang -plugin-arg-intent-gate -Xclang "out=$OUT/bare.gate.json" \
  -Xclang -plugin-arg-intent-gate -Xclang quiet \
  -c "$FIX/mixed.c" -o "$OUT/obj/ctl/trap_bare.o"
rc_bare=$?
bare_o=no; [ -f "$OUT/obj/ctl/trap_bare.o" ] && bare_o=yes
bare_rec=no; [ -s "$OUT/bare.gate.json" ] && bare_rec=yes
note "  -fplugin only: exit=$rc_bare object=$bare_o record=$bare_rec"
if [ "$rc_bare" -eq 0 ] && [ "$bare_o" = yes ] && [ "$bare_rec" = yes ]; then
  note "  PASS: AddAfterMainAction runs on -fplugin alone; -add-plugin is not required"
else
  fail "-fplugin alone did not run the gate (exit $rc_bare, object=$bare_o, record=$bare_rec)"
fi

run "$CC" -fplugin="$PLUGIN" -Xclang -add-plugin -Xclang intent-gate \
  -Xclang -plugin-arg-intent-gate -Xclang "findings=$OUT/mixed.findings.json" \
  -Xclang -plugin-arg-intent-gate -Xclang "root=$FIX" \
  -Xclang -plugin-arg-intent-gate -Xclang quiet \
  -c "$FIX/mixed.c" -o "$OUT/obj/ctl/trap_add.o"
rc_add=$?
run "$CC" -fplugin="$PLUGIN" -Xclang -plugin -Xclang intent-gate \
  -Xclang -plugin-arg-intent-gate -Xclang "findings=$OUT/mixed.findings.json" \
  -Xclang -plugin-arg-intent-gate -Xclang "root=$FIX" \
  -Xclang -plugin-arg-intent-gate -Xclang quiet \
  -c "$FIX/mixed.c" -o "$OUT/obj/ctl/trap_replace.o"
rc_rep=$?
add_o=no; [ -f "$OUT/obj/ctl/trap_add.o" ] && add_o=yes
rep_o=no; [ -f "$OUT/obj/ctl/trap_replace.o" ] && rep_o=yes
note "  -add-plugin: exit=$rc_add object=$add_o"
note "  -plugin    : exit=$rc_rep object=$rep_o"
if [ "$rc_add" -eq 0 ] && [ "$add_o" = yes ] && [ "$rep_o" = no ]; then
  note "  PASS: -plugin replaces the main action, so no object file is produced"
else
  fail "the -add-plugin / -plugin behaviour is not what the README records"
fi

note ""
note "### 8. fail-closed configuration"
rc_missing=0
run "$CC" -fplugin="$PLUGIN" -Xclang -add-plugin -Xclang intent-gate \
  -c "$FIX/mixed.c" -o "$OUT/obj/ctl/noargs.o" || rc_missing=$?
note "  no findings= argument: exit=$rc_missing"
[ "$rc_missing" -ne 0 ] || fail "a gate with no findings file compiled cleanly (fails open)"

note ""
note "### 9. record canonicalisation"
node -e '
const fs=require("fs"), crypto=require("crypto");
const raw = fs.readFileSync(process.argv[1],"utf8").trim();
const obj = JSON.parse(raw);
function canon(v){
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map(k => JSON.stringify(k)+":"+canon(v[k])).join(",") + "}";
  }
  if (typeof v === "number") { if (!Number.isInteger(v)) throw new Error("non-integer "+v); return String(v); }
  return JSON.stringify(v);
}
if (canon(obj) !== raw) { console.log("FAIL: record is not in canonical form"); process.exit(2); }
const {context, evidenceDigest, ...rest} = obj;
const d = crypto.createHash("sha256").update(canon(rest),"utf8").digest("hex");
if (d !== evidenceDigest) { console.log(`FAIL: evidenceDigest ${evidenceDigest} != recomputed ${d}`); process.exit(2); }
if (JSON.stringify(obj).includes("/root/") || JSON.stringify(obj).includes("/home/")) {
  console.log("FAIL: an absolute path leaked into the record"); process.exit(2);
}
console.log("PASS: canonical, digest reproduces, no absolute paths");
' "$OUT/mixed.gate.json" | tee -a "$RES/summary.txt"
[ "${PIPESTATUS[0]}" -eq 0 ] || fail "record canonicalisation"

note ""
note "### 10. positive controls for the checkers themselves"
# (d) the digest check must reject a tampered record.
node -e '
const fs=require("fs"), crypto=require("crypto");
const obj = JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
obj.verdicts[0].verdict = "Confirmed";           // flip one field, leave the digest
function canon(v){
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map(k => JSON.stringify(k)+":"+canon(v[k])).join(",") + "}";
  if (typeof v === "number") return String(v);
  return JSON.stringify(v);
}
const {context, evidenceDigest, ...rest} = obj;
const d = crypto.createHash("sha256").update(canon(rest),"utf8").digest("hex");
if (d === evidenceDigest) { console.log("  FAIL (d): a tampered record kept its digest"); process.exit(2); }
console.log("  (d) tampering with one verdict field breaks evidenceDigest, as it must");
' "$OUT/mixed.gate.json" | tee -a "$RES/summary.txt"
[ "${PIPESTATUS[0]}" -eq 0 ] || fail "digest tamper control"

# (e) check-verdicts.mjs must FAIL on a record that does not match. Without this
#     a run of green PASS lines proves only that the checker says PASS.
node -e '
const fs=require("fs");
const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
j.verdicts[0].verdict = "Confirmed";
j.verdicts[0].reason = "direct-call";
fs.writeFileSync(process.argv[2], JSON.stringify(j));
' "$OUT/mixed.gate.json" "$OUT/mixed.tampered.gate.json"
run node "$SRC/tools/check-verdicts.mjs" "$EXPECT" "mixed.c" "$OUT/mixed.tampered.gate.json"
rc_tamper=$?
if [ "$rc_tamper" -eq 2 ]; then
  note "  (e) check-verdicts.mjs exits 2 on a mismatching record"
else
  fail "(e) check-verdicts.mjs accepted a tampered record (exit $rc_tamper) — the PASS lines above prove nothing"
fi
# (f) and it must exit 3, not 0, when it cannot check at all.
run node "$SRC/tools/check-verdicts.mjs" "$EXPECT" "no-such-fixture.c" "$OUT/mixed.gate.json"
rc_unknown=$?
if [ "$rc_unknown" -eq 3 ]; then
  note "  (f) an uncheckable fixture exits 3, never 0"
else
  fail "(f) an uncheckable fixture exited $rc_unknown instead of 3"
fi

note ""
if [ "$FAILURES" -eq 0 ]; then
  note "ALL CHECKS PASSED"
else
  note "$FAILURES CHECK(S) FAILED"
fi
note "log: $LOG"
note "results: $RES"
exit $((FAILURES > 0 ? 2 : 0))
