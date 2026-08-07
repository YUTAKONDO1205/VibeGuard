#!/usr/bin/env bash
# artefact-fixtures.sh — build the hardening matrix the artefact verifier was
# written against, and print what readelf actually shows for each row.
#
# WHY THIS EXISTS
#
# The detector must not be written against what readelf is expected to print.
# Three of the rows below contradict the obvious implementation:
#
#   * `-Wl,-z,norelro` removes PT_GNU_RELRO and LEAVES DT_FLAGS=BIND_NOW set.
#   * `-Wl,-z,relro,-z,lazy` keeps PT_GNU_RELRO and removes eager binding.
#   * DT_BIND_NOW is absent on every row, including the fully hardened one.
#
# And one row is the reason two properties abstain instead of answering: in a
# `-static` image `__stack_chk_fail` is defined whether or not the program was
# built with the protector.
#
#   bash artefact-fixtures.sh [workdir]
#
# `workdir` defaults to ./artefact-fixtures under the current directory. Nothing
# is written inside the repository unless you point it there. Requires gcc,
# readelf, objcopy and python3; it FAILS rather than skipping when one is
# missing, because a fixture matrix that quietly built fewer rows is a table
# with holes that read as agreement.

set -u

WORK="${1:-$PWD/artefact-fixtures}"
BIN="$WORK/bin"
OBS="$WORK/obs"

missing=0
for tool in gcc readelf objcopy python3; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "artefact-fixtures: required tool not found: $tool" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -gt 0 ]; then
  echo "artefact-fixtures: $missing tool(s) missing. Not skipping: a partial matrix is worse than none." >&2
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$BIN" "$OBS" || exit 1
cd "$WORK" || exit 1

# The control string is the residue extractor's 0-vs-nonzero control: an
# extractor that has stopped finding anything must be distinguishable from an
# artefact that is clean.
cat > fixture.c <<'EOF'
#include <stdio.h>
#include <string.h>

const char *SECRET = "AKIAIOSFODNN7EXAMPLE-artefact-residue-marker";
const char *CONTROL_STRING = "artefact-control-string-always-present";

/* Protector-eligible and fortifiable: a real char array on the stack. */
int copy_it(const char *in) {
  char buf[64];
  strcpy(buf, in);
  printf("%s\n", buf);
  return (int) strlen(buf);
}

/* CONTROL: an effect that cannot be optimised away. */
volatile int control_sink;
int control(int x) { control_sink = x + 1; return control_sink; }

int main(int argc, char **argv) {
  control(argc);
  if (argc > 1) return copy_it(argv[1]);
  puts(CONTROL_STRING);
  return 0;
}
EOF

cat > wx.c <<'EOF'
#include <stdio.h>
__attribute__((section(".vgwx"))) volatile unsigned char trampoline[16] = {0x90};
volatile int control_sink;
int control(int x) { control_sink = x + 1; return control_sink; }
int main(int argc, char **argv) { control(argc); printf("%p\n", (void *) trampoline); return 0; }
EOF

cat > lib.c <<'EOF'
volatile int control_sink;
int control(int x) { control_sink = x + 1; return control_sink; }
int libfn(int a) { return control(a) * 2; }
EOF

built=0
failed=0
build() {
  name="$1"; shift
  if gcc -o "$BIN/$name" fixture.c "$@" 2> "$OBS/$name.err"; then
    built=$((built + 1))
    echo "BUILD OK   $name :: $*"
  else
    failed=$((failed + 1))
    echo "BUILD FAIL $name :: $*"
    sed 's/^/    /' "$OBS/$name.err"
  fi
}

OFF="-fno-stack-protector -U_FORTIFY_SOURCE"

build sp-on       -O2 -fstack-protector-strong -U_FORTIFY_SOURCE
build sp-off      -O2 $OFF
build pie-on      -O2 -fPIE -pie $OFF
build pie-off     -O2 -fno-pie -no-pie $OFF
build relro-full  -O2 -Wl,-z,relro,-z,now $OFF
build relro-part  -O2 -Wl,-z,relro,-z,lazy $OFF
build relro-none  -O2 -Wl,-z,norelro $OFF
build nx-on       -O2 -Wl,-z,noexecstack $OFF
build nx-off      -O2 -Wl,-z,execstack $OFF
build fortify-on  -O2 -D_FORTIFY_SOURCE=2 -fno-stack-protector
build fortify-off -O0 -U_FORTIFY_SOURCE -fno-stack-protector
build buildid-on  -O2 -Wl,--build-id=sha1 $OFF
build buildid-off -O2 -Wl,--build-id=none $OFF
build dbg-on      -O0 -g $OFF
build dbg-off     -O2 -g0 $OFF
build rpath       -O2 -fstack-protector-strong -Wl,-rpath,/opt/vendor/lib
build hardened    -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
                  -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--build-id=sha1 -g0
build unhardened  -O0 -fno-stack-protector -U_FORTIFY_SOURCE -fno-pie -no-pie \
                  -Wl,-z,norelro -Wl,-z,execstack -Wl,--build-id=none -g
build static-hardened -O2 -static -fstack-protector-strong -D_FORTIFY_SOURCE=2
build static-plain    -O2 -static $OFF

if [ -f "$BIN/hardened" ]; then
  cp "$BIN/hardened" "$BIN/hardened-stripped" && strip "$BIN/hardened-stripped" \
    && { built=$((built + 1)); echo "BUILD OK   hardened-stripped :: strip"; }
fi

if gcc -O2 -fPIC -shared -o "$BIN/libshared.so" lib.c -fno-stack-protector 2> "$OBS/libshared.err"; then
  built=$((built + 1)); echo "BUILD OK   libshared.so :: -shared -fPIC"
else
  failed=$((failed + 1)); echo "BUILD FAIL libshared.so"; sed 's/^/    /' "$OBS/libshared.err"
fi

# A section that is allocated, writable AND executable. gcc will not emit the
# flag combination from source, so the section is created and then re-flagged.
if gcc -O2 -o "$BIN/wx-on" wx.c -Wl,-z,noexecstack 2> "$OBS/wx-on.err"; then
  objcopy --set-section-flags .vgwx=alloc,load,code,contents "$BIN/wx-on" "$BIN/wx-on.tmp" 2> "$OBS/wx-objcopy.err" \
    && mv "$BIN/wx-on.tmp" "$BIN/wx-on"
  built=$((built + 1)); echo "BUILD OK   wx-on :: .vgwx re-flagged W+A+X"
else
  failed=$((failed + 1)); echo "BUILD FAIL wx-on"; sed 's/^/    /' "$OBS/wx-on.err"
fi

echo
echo "built=$built failed=$failed"
if [ "$failed" -gt 0 ]; then
  echo "artefact-fixtures: the matrix is incomplete; do not read the table below as agreement." >&2
  exit 1
fi
if [ "$built" -eq 0 ]; then
  echo "artefact-fixtures: nothing was built. An empty matrix is not a pass." >&2
  exit 1
fi

# ── the table ───────────────────────────────────────────────────────────────
echo
echo "===== STRUCTURAL FIELDS, read from the bytes (no tool output is parsed) ====="
python3 - "$BIN" <<'PY'
import struct, glob, os, sys
BIN = sys.argv[1]

def read(p):
    b = open(p, 'rb').read()
    et = struct.unpack_from('<H', b, 16)[0]
    phoff = struct.unpack_from('<Q', b, 32)[0]
    shoff = struct.unpack_from('<Q', b, 40)[0]
    pes, pn = struct.unpack_from('<HH', b, 54)
    ses, sn, sx = struct.unpack_from('<HHH', b, 58)
    ph = [struct.unpack_from('<II', b, phoff + i * pes) for i in range(pn)]
    sh = []
    for i in range(sn):
        o = shoff + i * ses
        nm, ty = struct.unpack_from('<II', b, o)
        flg, addr, off, size = struct.unpack_from('<QQQQ', b, o + 8)
        link, info = struct.unpack_from('<II', b, o + 40)
        ent = struct.unpack_from('<Q', b, o + 56)[0]
        sh.append(dict(nm=nm, ty=ty, flg=flg, off=off, size=size, link=link, ent=ent))
    so = sh[sx]['off']
    for s in sh:
        e = b.index(b'\0', so + s['nm']); s['name'] = b[so + s['nm']:e].decode('latin1')
    dyn = []
    for s in sh:
        if s['ty'] == 6:
            for i in range(s['size'] // 16):
                tag, val = struct.unpack_from('<qQ', b, s['off'] + i * 16)
                dyn.append((tag, val))
                if tag == 0: break
    return b, et, ph, sh, dyn

rows = []
for p in sorted(glob.glob(BIN + '/*')):
    n = os.path.basename(p)
    b, et, ph, sh, dyn = read(p)
    gs = [f for t, f in ph if t == 0x6474e551]
    relro = any(t == 0x6474e552 for t, _ in ph)
    interp = any(t == 3 for t, _ in ph)
    fl = [v for t, v in dyn if t == 30]
    f1 = [v for t, v in dyn if t == 0x6ffffffb]
    bn = any(t == 24 for t, _ in dyn)
    und, dfn = set(), set()
    for s in sh:
        if s['ty'] in (2, 11) and s['ent']:
            strs = sh[s['link']]['off']
            for i in range(s['size'] // s['ent']):
                o = s['off'] + i * s['ent']
                stn, inf, oth, shx = struct.unpack_from('<IBBH', b, o)
                e = b.index(b'\0', strs + stn); nm = b[strs + stn:e].decode('latin1').split('@')[0]
                if nm: (und if shx == 0 else dfn).add(nm)
    js = set()
    dynsym = [s for s in sh if s['ty'] == 11]
    names = []
    if dynsym:
        ds = dynsym[0]; strs = sh[ds['link']]['off']
        for i in range(ds['size'] // ds['ent']):
            stn = struct.unpack_from('<I', b, ds['off'] + i * ds['ent'])[0]
            e = b.index(b'\0', strs + stn); names.append(b[strs + stn:e].decode('latin1'))
    for s in sh:
        if s['ty'] == 4 and s['ent']:
            for i in range(s['size'] // s['ent']):
                info = struct.unpack_from('<Q', b, s['off'] + i * s['ent'] + 8)[0]
                if info & 0xffffffff == 7:
                    k = info >> 32
                    if k < len(names): js.add(names[k].split('@')[0])
    wx = [s['name'] for s in sh if (s['flg'] & 1) and (s['flg'] & 4)]
    dbg = [s['name'] for s in sh if s['name'].startswith('.debug')]
    bid = any(s['name'] == '.note.gnu.build-id' for s in sh)
    rows.append((n, et, gs[0] if gs else None, relro, interp,
                 hex(fl[0]) if fl else '-', hex(f1[0]) if f1 else '-', bn,
                 '__stack_chk_fail' in js or '__stack_chk_fail' in und,
                 sorted(x for x in js if x.endswith('_chk') and 'stack_chk' not in x),
                 bid, wx, len(dbg)))

hdr = ('fixture', 'e_type', 'STACK', 'RELRO', 'INTERP', 'DT_FLAGS', 'DT_FLAGS_1', 'BIND_NOW', 'SP', 'CHK', 'BID', 'W+X', 'dbg')
print(f'{hdr[0]:<20}{hdr[1]:>7}{hdr[2]:>7}{hdr[3]:>7}{hdr[4]:>7}{hdr[5]:>12}{hdr[6]:>12}{hdr[7]:>9}{hdr[8]:>6}  {hdr[9]:<18}{hdr[10]:>5}  {hdr[11]}  {hdr[12]}')
for r in rows:
    print(f'{r[0]:<20}{r[1]:>7}{str(r[2]):>7}{str(r[3]):>7}{str(r[4]):>7}{r[5]:>12}{r[6]:>12}{str(r[7]):>9}{str(r[8]):>6}  {",".join(r[9]) or "-":<18}{str(r[10]):>5}  {r[11] or "-"}  {r[12]}')
PY

echo
echo "===== residue: the control string and the forbidden marker ====="
for f in hardened unhardened; do
  [ -f "$BIN/$f" ] || continue
  printf '%-12s control=%s secret=%s\n' "$f" \
    "$(grep -c 'artefact-control-string-always-present' "$BIN/$f" 2>/dev/null || echo 0)" \
    "$(grep -c 'AKIAIOSFODNN7EXAMPLE' "$BIN/$f" 2>/dev/null || echo 0)"
done

echo
echo "fixtures are in $BIN"
