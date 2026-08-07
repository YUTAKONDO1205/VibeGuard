#!/bin/bash
# Rebuild the captured link maps and input traces under testdata/.
#
# Everything in testdata/ is real linker output. A hand-written map agrees with
# the parser by construction and proves only that the author was consistent with
# themselves; these files disagreed with the parser three times while it was
# being written, which is what a fixture is for.
#
#   VG_LINK_LAB=<dir> bash tools/make-fixtures.sh
#
# The build goes to VG_LINK_LAB (default ~/vg-lab/link-integrity, per
# compiler/schema/interfaces.md §1: sources are tracked, builds are not). Only
# the small text captures are copied back into the tree.
#
# Requires clang-18 and lld. It FAILS if they are missing — a fixture generator
# that silently produces nothing leaves the old captures in place and the next
# reader believes they describe the current toolchain.
set -u

LAB=${VG_LINK_LAB:-$HOME/vg-lab/link-integrity}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../testdata
SRC=$LAB/fixtures

CC=${CC:-clang-18}
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "FAIL: $CC not found. Set CC, or install it; this script does not fall back." >&2
  exit 1
fi

rm -rf "$SRC"
mkdir -p "$SRC" "$OUT"
cd "$SRC" || exit 1

# CONTROL: control_fn's zeroing cannot be optimised away, because the buffer
# escapes into another translation unit. Every fixture carries it, and a
# measurement in which the control disappears is broken rather than interesting.
# Counted the way interfaces.md §4 requires: CALL SITES within one function, not
# the surviving `declare` line, and not module-wide (after inlining the
# out-of-line original is still there).
cat > main.c <<'EOF'
#include <string.h>
extern int helper(int);
extern void opaque(char *p);
volatile int sink;

/* CONTROL — survives -O2: opaque() may read the buffer. */
int control_fn(int n) { char b[16]; memset(b, 0, sizeof b); opaque(b); return n; }

/* TARGET — the zeroing is dead and -O2 removes it. */
int target_fn(int n) { char b[16]; memset(b, 0, sizeof b); return n; }

__attribute__((constructor)) static void ctor_main(void) { sink = 1; }

int main(void) { return helper(control_fn(3)) + target_fn(1); }
EOF

cat > helper.c <<'EOF'
volatile int hsink;
void opaque(char *p) { hsink = p[0]; }
int helper(int x) { return x * 2; }
EOF

# The unapproved input: it also has a constructor, so it reaches .init_array.
# An object that runs code before main is the shape worth detecting, not one
# that merely adds a function nobody calls.
cat > rogue.c <<'EOF'
volatile int rogue_sink;
__attribute__((constructor)) static void ctor_rogue(void) { rogue_sink = 1; }
int rogue_fn(int x) { return x + 1; }
EOF

cat > arch.c <<'EOF'
volatile int asink;
__attribute__((constructor)) static void ctor_arch(void) { asink = 2; }
int arch_fn(int x) { return x + 7; }
EOF

cat > mainarc.c <<'EOF'
extern int helper(int);
extern int arch_fn(int);
int main(void) { return helper(1) + arch_fn(2); }
EOF

cat > extra.ld <<'EOF'
SECTIONS { .injected_note : { *(.comment) } } INSERT AFTER .text;
EOF

set -e
for u in main helper rogue arch mainarc; do "$CC" -c -O2 "$u.c" -o "$u.o"; done
ar rcs libarch.a arch.o
set +e

echo "== fixture control: memset CALL SITES per function, and the declare line =="
"$CC" -O0 -S -emit-llvm main.c -o main.O0.ll
"$CC" -O2 -S -emit-llvm main.c -o main.O2.ll
for lvl in O0 O2; do
  decl=$(grep -c '^declare.*llvm\.memset' "main.$lvl.ll")
  ctl=$(awk '/^define .*@control_fn/,/^}/' "main.$lvl.ll" | grep -c 'call void @llvm\.memset')
  tgt=$(awk '/^define .*@target_fn/,/^}/' "main.$lvl.ll" | grep -c 'call void @llvm\.memset')
  echo "   -$lvl  control=$ctl target=$tgt declares=$decl"
  if [ "$ctl" -eq 0 ]; then
    echo "FAIL: the control lost its zeroing at -$lvl. The fixture is broken, not the toolchain." >&2
    exit 1
  fi
done

link() { # name, then link arguments
  local n=$1; shift
  "$CC" -fuse-ld=lld "-Wl,-Map=$n.map" -Wl,-t "$@" -o "$n.bin" > "$n.t" 2> "$n.err" || {
    echo "FAIL: link $n" >&2; cat "$n.err" >&2; exit 1; }
  printf '   %-4s map=%s trace=%s\n' "$n" "$(wc -c < "$n.map")" "$(wc -l < "$n.t")"
}

echo "== links =="
link neg main.o helper.o
link pos main.o helper.o rogue.o
link arc mainarc.o helper.o -L. -larch
link scr -Wl,-T,extra.ld main.o helper.o

echo "== capture =="
n=0
for f in neg pos arc scr; do
  # `.map.txt`, not `.map`. The repository ignores `compiler/**/*.map` — build
  # products, correctly — and a fixture that is never committed is a suite that
  # only ever runs on the machine that generated it. The ignore file is not this
  # component's to edit, so the capture is named out of its way instead.
  cp "$f.map" "$OUT/$f.map.txt"; cp "$f.t" "$OUT/$f.trace"; n=$((n + 2))
done
# The first 64 bytes of a real artefact, hex-encoded rather than binary so the
# tree stays text and the repository's own scanners can read it.
for b in neg pos; do head -c 64 "$b.bin" | xxd -p -c 32 > "$OUT/$b.elfhdr.hex"; n=$((n + 1)); done

echo "captured=$n"
if [ "$n" -eq 0 ]; then echo "FAIL: nothing captured" >&2; exit 1; fi

if grep -qE '/(home|Users)/|/mnt/[a-z]/' "$OUT"/*.map.txt "$OUT"/*.trace; then
  echo "FAIL: an account-shaped path reached the captured testdata" >&2
  exit 1
fi
echo "ok: no account-shaped path in the captures"
