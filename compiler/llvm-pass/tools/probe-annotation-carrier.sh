#!/bin/bash
# The measurements the metadata channel's design rests on, reproducible.
#
#   bash compiler/llvm-pass/tools/probe-annotation-carrier.sh
#
# Three questions, each answered by compiling something and looking, not by
# reading documentation:
#
#   1. Does __attribute__((annotate(...))) reach IR with no Clang plugin loaded,
#      and in what form? (If it does not, the whole channel has no input.)
#   2. Is the annotation removable by the optimiser on its own -- i.e. can the
#      "metadata went, processing stayed" cell be reached the obvious way?
#   3. Is the annotation inert, or does carrying one change what the optimiser
#      emits?
#
# This prints a table and decides nothing. It writes only into its own scratch
# directory under the lab; nothing is written under compiler/.
set -u

LAB=${IRCK_DUAL_LAB:-$HOME/vg-lab/llvm-pass-dual}
W="$LAB/carrier-probe"
CC=${IRCK_CC:-clang-18}
OPT=${IRCK_OPT:-opt-18}

rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 3

cat > carriers.c <<'EOF'
#include <string.h>
void sink(void *p);
void fill(char *p, unsigned n);

/* function-level annotation + local-variable annotation, on a buffer that
   escapes and whose wipe is read afterwards. */
__attribute__((annotate("vg:property:erasure.wipe")))
void both_carriers(void) {
    __attribute__((annotate("vg:property:erasure.wipe"))) char b[16];
    fill(b, 16);
    memset(b, 0, 16);
    sink(b);
}

/* an annotated local that nothing ever touches. If anything DCEs annotations,
   this is where it shows. */
void untouched(void) {
    __attribute__((annotate("vg:property:erasure.wipe"))) char b[16];
    (void)b;
}
EOF

# --- 1. does the carrier reach IR, and where -------------------------------
echo "=== 1. carrier survival by optimisation level ==================="
printf '%-6s %-22s %-22s %-14s %s\n' \
       "-O" "global.annotations" "var.annotation calls" "memset calls" "allocas"
for O in 0 1 2 3; do
  $CC "-O$O" -S -emit-llvm -o "carriers-O$O.ll" carriers.c || exit 3
  ga=$(grep -c '^@llvm.global.annotations' "carriers-O$O.ll" || true)
  va=$(grep -c 'call void @llvm.var.annotation' "carriers-O$O.ll" || true)
  ms=$(grep -c 'call void @llvm.memset' "carriers-O$O.ll" || true)
  al=$(grep -cE '= alloca ' "carriers-O$O.ll" || true)
  printf '%-6s %-22s %-22s %-14s %s\n' "-O$O" "$ga" "$va" "$ms" "$al"
done
echo
echo "  Read this as: the annotation is not removable on its own. The local"
echo "  annotation on a buffer nobody touches is still there at -O3, and it"
echo "  keeps that buffer's alloca alive with it. llvm.var.annotation is"
echo "  declared memory(inaccessiblemem: readwrite), which is why:"
grep -h 'attributes #' "carriers-O2.ll" | grep 'inaccessiblemem' || \
  echo "  (attribute line not found -- the claim above is NOT confirmed on this toolchain)"

# --- 2. is there a second, fragile carrier (!annotation metadata)? ----------
echo
echo "=== 2. does Annotation2MetadataPass produce !annotation metadata? ==="
$OPT -passes=annotation2metadata -S carriers-O0.ll -o carriers-a2m.ll 2>/dev/null || {
  echo "  $OPT unavailable; NOT MEASURED"; }
if [ -f carriers-a2m.ll ]; then
  n=$(grep -c '!annotation' carriers-a2m.ll || true)
  echo "  !annotation occurrences after the pass: $n"
  echo "  (0 means there is no second carrier to read here, which is why the"
  echo "   metadata channel has no reader for one.)"
fi

# --- 3. is an annotation inert? --------------------------------------------
cat > pinned.c <<'EOF'
#include <string.h>
void sink(void *p);
void fill(char *p, unsigned n);
ANNOT
static void scrub(char *p, unsigned n) { memset(p, 0, n); sink(p); }
void caller(void) { char t[16]; fill(t, 16); scrub(t, 16); }
EOF
sed 's/^ANNOT$/__attribute__((annotate("vg:property:erasure.wipe")))/' pinned.c > pinned-annot.c
sed 's/^ANNOT$//' pinned.c > pinned-plain.c

echo
echo "=== 3. one attribute apart: is the annotation inert at -O2? ========"
printf '%-16s %-12s %-16s %s\n' "variant" "definitions" "scrub defined?" "memset calls"
for v in annot plain; do
  $CC -O2 -S -emit-llvm -o "pinned-$v.ll" "pinned-$v.c" || exit 3
  d=$(grep -c '^define' "pinned-$v.ll" || true)
  s=$(grep -c '^define internal void @scrub' "pinned-$v.ll" || true)
  m=$(grep -c 'call void @llvm.memset' "pinned-$v.ll" || true)
  printf '%-16s %-12s %-16s %s\n' "$v" "$d" "$s" "$m"
done
echo
echo "  If the two rows differ, the annotation is not inert: the entry in"
echo "  @llvm.global.annotations counts as a use and keeps a static function"
echo "  alive that would otherwise be inlined away and deleted. 'Annotate"
echo "  everything' is then not a free measurement."
echo
echo "artefacts: $W"
