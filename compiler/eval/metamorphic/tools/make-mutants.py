#!/usr/bin/env python3
"""Write the metamorphic specimens into the lab, on the side that produces them.

    python3 compiler/eval/metamorphic/tools/make-mutants.py
    VG_META_LAB=/somewhere python3 .../make-mutants.py

Same rule as compiler/llvm-pass/tools/make-ladder.sh and tools/make-fixtures.sh,
and for the same reason: a fixture committed under compiler/ is a measurement
input in the published tree, which the boundary guard fails on. Generating the
bytes keeps them reproducible from the tracked tree without putting them in it --
THIS SCRIPT IS THE SPECIMEN SET, and it is reviewable as one.

Every specimen is one translation unit, compiled with -c or -S only, into a lab
outside the repository. Nothing here is ever linked, so every opaque producer and
consumer can stay an undefined extern and no optimisation level can see through
one.

WHAT A MUTANT IS, AND THE ONE THING THAT WOULD MAKE THIS WHOLE LANE VACUOUS

A mutant is the base translation unit with ONE deterministic text transformation
applied. The transformation is expressed as "replace the block of function F with
this text", never as a line number or a regular expression over the whole file:
compiler/eval/second-vendor's C2 control deletes by line number and says why --
its fixture carries the identical `memset(...)` text on two lines -- and a
line-numbered edit is right about a file until the file moves. A block edit
names what it is changing.

The failure this lane would not notice is a mutant that is byte-identical to its
base, because then every R2 operator reads `not-expressed` and the lane reports a
compiler that declined to take bait nobody offered. So the digests are compared
here, at emit time, and an equal pair is a refusal rather than a run.

THE OBSERVER'S THIRD SILENT FAILURE MODE, FENCED HERE AND AGAIN IN THE PRODUCER

A subject function name that resolves to nothing gives rc 0, an empty stderr, a
non-empty log, a HELD control, and only the subject's rows missing -- which at a
glance is indistinguishable from a property that was never there. So after
emitting each file this script reads the function names back OUT OF THE EMITTED
BYTES and refuses if any planned subject or control is not among them. A list
kept by hand beside the file can be right about a file that has changed, so the
list is DERIVED and not kept. The producer re-checks the same thing against the
`fn=` lines below, because two fences at the two places that could each be wrong
alone is the arrangement run-ladder.sh already uses.

OUTPUT, key=value on stdout, in the shape observe-config.sh's manifests use:

    lab=<absolute path to the lab>            (stdout only -- never a record)
    generatorVersion=<integer>
    generatorSha256=<sha256 of this file>
    catalogueSha256=<sha256 of catalogue.json>
    specimen=<specimenId>|<path relative to the lab>|<sha256 of the bytes>
    fn=<specimenId>|<one defined function name>          (repeated)
    cell=<operatorId>|<extractor>|<baseSpecimen>|<mutantSpecimen>|<baseSubject>
          |<mutantSubject>|<control>|<symbols>|<crossVendor>|<asmSymbols>
          |<allowInlineZeroStore>                        (repeated, one per cell)

`lab=` is the only absolute path this script emits and it goes to stdout for a
human, never into a document: interfaces.md section 5 keeps host paths out of
anything digested, and every path on a `specimen=` line is relative to the lab
for that reason.

Exit codes: 0 the specimens are on disk and every planned name resolves in them.
1 something about the catalogue, the recipes or the emitted bytes makes the set
not measurable -- an anchor that is not unique, a mutant equal to its base, a
planned name the bytes do not define, an operator with no recipe or a recipe with
no operator. The producer turns a 1 here into its own exit 3, because a specimen
set that could not be built is a check that could not be made.
"""

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOGUE = os.path.join(HERE, "..", "catalogue.json")
LAB = os.environ.get("VG_META_LAB", os.path.expanduser("~/vg-lab/metamorphic"))

# Bumped when a base template or a recipe changes such that a reading taken
# before the change cannot be read against one taken after it. `generatorSha256`
# is the better identity and travels beside this integer; the integer is kept for
# the reason build-ladder-frontier.py keeps one -- a coarse number a reader can
# compare without holding both generators.
GENERATOR_VERSION = 1

# Prefix every generated function name shares, so that the names can be read back
# out of the emitted bytes with one pattern. Chosen not to collide with the
# ladder's `vgl_`: two instruments' specimens must not be confusable in a log.
NAME_PREFIX = "meta_"

# A definition, not a declaration: the name is followed by a parameter list with
# no nested parentheses and then an opening brace. Every definition emitted below
# satisfies that on one line; the declarations end in `;` and every call site in
# a body is followed by `;` or by another `)`, so neither can be mistaken for a
# definition here. Same predicate as make-ladder.sh:218, in Python.
DEFN_RE = re.compile(r"\b(" + NAME_PREFIX + r"[A-Za-z0-9_]*)\s*\([^()]*\)\s*\{")


class Refused(Exception):
    """Something that makes the specimen set not measurable. Every refusal
    leaves by one door so that none of them can be a return 0."""


# ---------------------------------------------------------------------------
# The base translation units
# ---------------------------------------------------------------------------
#
# One base per shape. Each carries the shape's co-resident CONTROL and one
# subject per operator, so that one operator's edit cannot move another
# operator's reading -- with a single shared subject, deleting a wipe for R2a
# would delete the R1 cells' subject too and the whole shape would read from one
# mutant.

BASE_WIPE = """\
/* Metamorphic specimens, wipe shape. Emitted by tools/make-mutants.py.
 *
 * Never committed under compiler/: interfaces.md section 1 keeps measurement
 * inputs out of the published tree. One translation unit, compiled with -c or -S
 * only and never linked, so the opaque producer and consumer below stay
 * undefined externs at every optimisation level.
 *
 * Buffer sizes are pairwise-distinct primes. ir.wipe-effect decides LOST from
 * NOT_APPLICABLE by an alloca-SIZE census, and make-ladder.sh records that two
 * objects of one size in a unit made a promoted buffer read as a deleted wipe.
 */

#include <string.h>

extern void meta_fill(void *p, unsigned long n);
extern void meta_use(const void *p, unsigned long n);

/* THE CONTROL, co-resident with every subject here (interfaces.md section 4).
 * The zeros are read after they are written, so no level may remove this wipe. A
 * measurement in which THIS count also fell to zero is a broken measurement and
 * not a finding, which is why it is in the same unit rather than in a file of
 * its own. */
void meta_w_ctl(void) {
  unsigned char b[101];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_rename(void) {
  unsigned char b[59];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_size(void) {
  unsigned char b[61];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

/* Two objects of different sizes, so that the swap in W-R1-REORDER is between
 * statements that touch different memory and neither of which reads the wiped
 * buffer's zeros. */
void meta_w_reorder(void) {
  unsigned char b[67];
  unsigned char t[71];
  meta_fill(b, sizeof b);
  meta_fill(t, sizeof t);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
  meta_use(t, sizeof t);
}

void meta_w_addfn(void) {
  unsigned char b[73];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_spell(void) {
  unsigned char b[79];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_del(void) {
  unsigned char b[83];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_dead(void) {
  unsigned char b[89];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_zerolen(void) {
  unsigned char b[97];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}

void meta_w_unpin(void) {
  unsigned char b[103];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}
"""

BASE_GUARDED = """\
/* Metamorphic specimens, guarded shape. Emitted by tools/make-mutants.py.
 *
 * Scalar bodies with no arrays, for the reason make-ladder.sh gives: a
 * stack-protector variant would add a canary branch, and ir.guarded-call's
 * live-branch gate counts branches PER UNIT rather than per call, so an extra
 * live branch anywhere in the unit would keep an already-folded guard counted.
 */

extern int meta_cond(void);
extern void meta_deny(void);
extern void meta_allow(void);
extern volatile int meta_flag;

/* THE CONTROL. The condition comes from outside the translation unit, so neither
 * the branch nor the deny call can be folded at any level. */
void meta_g_ctl(void) {
  if (meta_cond()) meta_deny();
}

void meta_g_invert(void) {
  if (meta_cond()) meta_deny();
  else meta_allow();
}

void meta_g_opaque(void) {
  if (meta_cond()) meta_deny();
}

void meta_g_addcode(void) {
  if (meta_cond()) meta_deny();
}

void meta_g_del(void) {
  if (meta_cond()) meta_deny();
}

void meta_g_static(void) {
  if (meta_cond()) meta_deny();
}

void meta_g_inline(void) {
  if (meta_cond()) meta_deny();
}
"""

BASE_FORBIDDEN = """\
/* Metamorphic specimens, forbidden-callee shape. Emitted by
 * tools/make-mutants.py.
 *
 * OPPOSITE POLARITY to the other two shapes: a non-zero count IS the finding,
 * and the control is inverted with it. properties.json states the rule -- the
 * control is a co-resident unit where the forbidden call is CERTAINLY still
 * present, which is what shows the extractor can still see one at this
 * optimisation level. A control chosen the other way round proves nothing.
 *
 * The asm labels pin the callee name the IR must show, so that one control can
 * hold one spelling while the subject's spelling is what moves. Same device as
 * the ladder's spelling anchors.
 */

#include <stdio.h>

extern int meta_cond(void);
extern void meta_work(void);

extern int meta_printf_lib(const char *, ...) __asm__("printf");
extern int meta_puts_lib(const char *) __asm__("puts");

/* CONTROL for every cell read through the `printf` list. The argument is a
 * runtime value, so no level rewrites this call to something else. */
void meta_f_ctl_printf(void) {
  meta_printf_lib("meta %d\\n", meta_cond());
}

/* CONTROL for the cell read through the `puts` list. Pinned by its asm label, so
 * the `puts` lane has a witness even at a level that performs no rewrite. */
void meta_f_ctl_puts(void) {
  meta_puts_lib("meta");
}

void meta_f_position(void) {
  meta_work();
  meta_printf_lib("meta %d\\n", meta_cond());
}

void meta_f_permitted(void) {
  meta_printf_lib("meta %d\\n", meta_cond());
}

void meta_f_introduce(void) {
  meta_work();
}

void meta_f_spell(void) {
  meta_work();
}
"""

BASES = {
    "wipe": BASE_WIPE,
    "guarded": BASE_GUARDED,
    "forbidden": BASE_FORBIDDEN,
}

# ---------------------------------------------------------------------------
# The recipes: specimenId -> (shape, [edit, ...])
# ---------------------------------------------------------------------------
#
# An edit is one of
#   ("replace", <function name>, <new block text>)
#   ("append",  None,            <text appended at the end of the unit>)
#   ("before",  <function name>, <text inserted immediately before the block>)
#
# Keyed by specimenId so that two operators may share one mutant -- F-R2S-PUTS
# and F-R2S-PRINTF read one specimen through two symbol lists, which is the whole
# point of that pair.

RECIPES = {
    # --- wipe ---------------------------------------------------------------
    "wipe.W-R1-RENAME": ("wipe", [
        ("replace", "meta_w_rename", """\
void meta_w_renamed_subject(void) {
  unsigned char scratch[59];
  meta_fill(scratch, sizeof scratch);
  memset(scratch, 0, sizeof scratch);
  meta_use(scratch, sizeof scratch);
}
"""),
    ]),
    "wipe.W-R1-SIZE": ("wipe", [
        ("replace", "meta_w_size", """\
void meta_w_size(void) {
  unsigned char b[113];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(b, sizeof b);
}
"""),
    ]),
    "wipe.W-R1-REORDER": ("wipe", [
        ("replace", "meta_w_reorder", """\
void meta_w_reorder(void) {
  unsigned char b[67];
  unsigned char t[71];
  meta_fill(t, sizeof t);
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  meta_use(t, sizeof t);
  meta_use(b, sizeof b);
}
"""),
    ]),
    "wipe.W-R1-ADDFN": ("wipe", [
        ("append", None, """
/* W-R1-ADDFN: unrelated, and outside the unit of count. */
unsigned meta_w_addfn_extra(unsigned x) {
  return x * 2654435761u + 1u;
}
"""),
    ]),
    "wipe.W-R1S-LOOP": ("wipe", [
        ("replace", "meta_w_spell", """\
void meta_w_spell(void) {
  unsigned char b[79];
  meta_fill(b, sizeof b);
  for (unsigned i = 0; i < 79u; i++) b[i] = 0;
  meta_use(b, sizeof b);
}
"""),
    ]),
    "wipe.W-R2A-DELETE": ("wipe", [
        ("replace", "meta_w_del", """\
void meta_w_del(void) {
  unsigned char b[83];
  meta_fill(b, sizeof b);
  meta_use(b, sizeof b);
}
"""),
    ]),
    "wipe.W-R2B-DEADZERO": ("wipe", [
        ("replace", "meta_w_dead", """\
void meta_w_dead(void) {
  unsigned char b[89];
  meta_fill(b, sizeof b);
  memset(b, 0, sizeof b);
}
"""),
    ]),
    "wipe.W-R2B-ZEROLEN": ("wipe", [
        ("replace", "meta_w_zerolen", """\
void meta_w_zerolen(void) {
  unsigned char b[97];
  meta_fill(b, sizeof b);
  memset(b, 0, 0);
  meta_use(b, sizeof b);
}
"""),
    ]),
    "wipe.W-R2C-UNPIN": ("wipe", [
        ("replace", "meta_w_unpin", """\
void meta_w_unpin(void) {
  unsigned char b[103];
  for (unsigned i = 0; i < 103u; i++) b[i] = (unsigned char)i;
  memset(b, 0, sizeof b);
}
"""),
    ]),

    # --- guarded ------------------------------------------------------------
    "guarded.G-R1-INVERT": ("guarded", [
        ("replace", "meta_g_invert", """\
void meta_g_invert(void) {
  if (!meta_cond()) meta_allow();
  else meta_deny();
}
"""),
    ]),
    "guarded.G-R1-OPAQUE": ("guarded", [
        ("replace", "meta_g_opaque", """\
void meta_g_opaque(void) {
  if (meta_flag) meta_deny();
}
"""),
    ]),
    "guarded.G-R1-ADDCODE": ("guarded", [
        ("append", None, """
/* G-R1-ADDCODE: unrelated, and outside the unit of count. It carries no
 * conditional branch, so it cannot feed ir.guarded-call's per-unit live-branch
 * gate even by accident. */
unsigned meta_g_addcode_extra(unsigned x) {
  return x ^ 0x9e3779b9u;
}
"""),
    ]),
    "guarded.G-R2A-DELETE": ("guarded", [
        ("replace", "meta_g_del", """\
void meta_g_del(void) {
  meta_allow();
}
"""),
    ]),
    "guarded.G-R2B-STATICZERO": ("guarded", [
        ("before", "meta_g_static", """\
/* G-R2B-STATICZERO. NOT `const`: a const initialiser is folded by the FRONT END,
 * so the branch would never reach the IR at all and the cell would read ABSENT at
 * every level, discriminating nothing. Measured on the ladder's c1 rung,
 * 2026-08-17. Written once and never again, so the OPTIMISER -- not the front
 * end -- is the thing that decides it. */
static int meta_g_zero = 0;

"""),
        ("replace", "meta_g_static", """\
void meta_g_static(void) {
  if (meta_g_zero) meta_deny();
}
"""),
    ]),
    "guarded.G-R2C-INLINE": ("guarded", [
        ("replace", "meta_g_inline", """\
/* G-R2C-INLINE. The caller is not decoration: a static function with no caller is
 * simply deleted, and the observer then reads unit-absent-effect-gone, which is
 * LOST and a different finding from this operator's declared NOT_APPLICABLE. With
 * a caller the deny site survives in the caller, the module-wide count outside the
 * control accounts for what the subject contributed, and the verdict is
 * NOT_APPLICABLE -- the unit lost its referent while the guard is still enforced. */
static void meta_g_inline(void) {
  if (meta_cond()) meta_deny();
}

void meta_g_inline_caller(void) {
  meta_g_inline();
}
"""),
    ]),

    # --- forbidden ----------------------------------------------------------
    "forbidden.F-R1-POSITION": ("forbidden", [
        ("replace", "meta_f_position", """\
void meta_f_position(void) {
  meta_printf_lib("meta %d\\n", meta_cond());
  meta_work();
}
"""),
    ]),
    "forbidden.F-R1-PERMITTED": ("forbidden", [
        ("replace", "meta_f_permitted", """\
void meta_f_permitted(void) {
  meta_printf_lib("meta %d\\n", meta_cond());
  meta_work();
}
"""),
    ]),
    "forbidden.F-R2-INTRODUCE": ("forbidden", [
        ("replace", "meta_f_introduce", """\
void meta_f_introduce(void) {
  meta_work();
  meta_printf_lib("meta %d\\n", meta_cond());
}
"""),
    ]),
    "forbidden.F-R2S-REWRITE": ("forbidden", [
        ("replace", "meta_f_spell", """\
/* F-R2S-*. A CONSTANT-string printf, deliberately: clang rewrites it to puts, so
 * the introduced call arrives on a different symbol list than the one the source
 * names. Read through `puts` (F-R2S-PUTS, graded) and through `printf`
 * (F-R2S-PRINTF, reported as data) over this one specimen. */
void meta_f_spell(void) {
  meta_work();
  printf("meta\\n");
}
"""),
    ]),
}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


def block_of(src, name):
    """The text of one function definition, from the line that opens it to the
    line that closes it.

    The opening line is matched anchored at column 0 and the closing brace must
    also be at column 0, which every definition in the templates above satisfies.
    A name that opens more than one block, or none, is a refusal rather than a
    guess: silently taking the first would let a recipe edit a function it did
    not name."""
    opens = [m for m in re.finditer(
        r"(?m)^((?:static\s+)?(?:void|unsigned|int)\s+" + re.escape(name)
        + r"\s*\([^()]*\)\s*\{)", src)]
    if len(opens) != 1:
        raise Refused("%r opens %d blocks in the base unit; a recipe anchor must "
                      "name exactly one" % (name, len(opens)))
    start = opens[0].start()
    end = src.find("\n}\n", start)
    if end == -1:
        raise Refused("%r has no closing brace at column 0" % name)
    return src[start:end + 3]


def apply_edits(base, edits):
    src = base
    for kind, fn, text in edits:
        if kind == "append":
            src = src + text
            continue
        block = block_of(src, fn)
        if src.count(block) != 1:
            raise Refused("the block of %r is not unique in the unit" % fn)
        if kind == "replace":
            src = src.replace(block, text)
        elif kind == "before":
            src = src.replace(block, text + block)
        else:
            raise Refused("unknown edit kind %r" % kind)
    return src


def defined_functions(text):
    """Read back out of the emitted bytes, never kept beside them."""
    return sorted(set(DEFN_RE.findall(text)))


def write_specimen(rel_path, text):
    """LF explicitly, and the bytes hashed are the bytes written.

    CRLF is the live risk on this checkout -- the tree is checked out on Windows
    with core.autocrlf and measured from WSL over /mnt/c -- and a generator that
    produced different bytes on two hosts would make an identical generator sha
    sit beside a different specimen sha. That is the environment leak the
    per-specimen digest exists to catch, so it is also worth not causing."""
    full = os.path.join(LAB, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    data = text.encode("utf-8")
    if b"\r" in data:
        raise Refused("%s would be written with a CR in it" % rel_path)
    with open(full, "wb") as fh:
        fh.write(data)
    return sha256_bytes(data)


def load_catalogue():
    with open(CATALOGUE, "r", encoding="utf-8") as fh:
        cat = json.load(fh)
    if cat.get("schemaVersion") != "vibeguard.metamorphic-catalogue/1":
        raise Refused("catalogue schemaVersion is %r; this generator emits for "
                      "%r only" % (cat.get("schemaVersion"),
                                   "vibeguard.metamorphic-catalogue/1"))
    return cat


def main():
    cat = load_catalogue()
    operators = cat["operators"]

    # A recipe with no operator, or a measurable operator with no recipe, is the
    # catalogue and the generator disagreeing about what this lane measures. Both
    # directions are checked, because only one of the two is visible from either
    # side alone.
    wanted = {}
    for op in operators:
        if op.get("measured") is False:
            continue
        sid = op.get("specimenId")
        if not sid:
            raise Refused("operator %s is measured and names no specimenId"
                          % op["operatorId"])
        if sid not in RECIPES:
            raise Refused("operator %s names specimen %s and this generator has "
                          "no recipe for it" % (op["operatorId"], sid))
        wanted.setdefault(sid, []).append(op)
    for sid in sorted(RECIPES):
        if sid not in wanted:
            raise Refused("this generator has a recipe for %s and no operator in "
                          "the catalogue names it; an unreferenced mutant is a "
                          "specimen nothing reads" % sid)

    specimens = []          # (specimenId, relPath, sha256)
    fns = {}                # specimenId -> [name, ...]
    base_sha = {}           # shape -> sha256
    base_id = {}            # shape -> specimenId

    shapes = sorted({RECIPES[s][0] for s in RECIPES})
    for shape in shapes:
        sid = "%s.base" % shape
        rel = os.path.join("specimens", shape, "base.c")
        sha = write_specimen(rel, BASES[shape])
        names = defined_functions(BASES[shape])
        if not names:
            raise Refused("no function definitions were found in the emitted %s"
                          % rel)
        specimens.append((sid, rel, sha))
        fns[sid] = names
        base_sha[shape] = sha
        base_id[shape] = sid

    for sid in sorted(RECIPES):
        shape, edits = RECIPES[sid]
        text = apply_edits(BASES[shape], edits)
        rel = os.path.join("specimens", shape, sid.split(".", 1)[1] + ".c")
        sha = write_specimen(rel, text)
        if sha == base_sha[shape]:
            raise Refused(
                "%s hashes identically to %s.base. A mutant compiled from the base "
                "is the failure this whole lane would not notice: every R2 operator "
                "would read not-expressed and the run would report a compiler that "
                "declined to take bait nobody offered." % (sid, shape))
        names = defined_functions(text)
        if not names:
            raise Refused("no function definitions were found in the emitted %s"
                          % rel)
        specimens.append((sid, rel, sha))
        fns[sid] = names

    # Every planned name checked against the bytes that were just written. This is
    # the fence for the observer's third silent failure mode; see the header.
    cells = []
    for op in operators:
        if op.get("measured") is False:
            continue
        sid = op["specimenId"]
        shape = RECIPES[sid][0]
        bsid = base_id[shape]
        for where, spec, name in (("base", bsid, op["baseSubject"]),
                                  ("mutant", sid, op["mutantSubject"]),
                                  ("base", bsid, op["control"]),
                                  ("mutant", sid, op["control"])):
            if name not in fns[spec]:
                raise Refused(
                    "operator %s names %s as its %s and %s does not define it. "
                    "Compiling anyway would give rc 0, an empty stderr, a held "
                    "control and only the subject's rows missing -- a reading "
                    "indistinguishable at a glance from a property that was never "
                    "there." % (op["operatorId"], name, where, spec))
        asm = op.get("asmEffect") or {}
        cells.append("|".join([
            op["operatorId"],
            op["extractor"],
            bsid,
            sid,
            op["baseSubject"],
            op["mutantSubject"],
            op["control"],
            ",".join(op["symbols"]),
            "1" if op.get("crossVendor") else "0",
            ",".join(asm.get("symbols") or []),
            "1" if asm.get("allowInlineZeroStore") else "0",
        ]))

    out = []
    out.append("lab=%s" % LAB)
    out.append("generatorVersion=%d" % GENERATOR_VERSION)
    out.append("generatorSha256=%s" % sha256_file(os.path.abspath(__file__)))
    out.append("catalogueSha256=%s" % sha256_file(CATALOGUE))
    for sid, rel, sha in specimens:
        out.append("specimen=%s|%s|%s" % (sid, rel.replace(os.sep, "/"), sha))
    for sid, _rel, _sha in specimens:
        for name in fns[sid]:
            out.append("fn=%s|%s" % (sid, name))
    for c in cells:
        out.append("cell=%s" % c)
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as exc:
        sys.stderr.write("make-mutants.py: %s\n" % exc)
        sys.exit(1)
