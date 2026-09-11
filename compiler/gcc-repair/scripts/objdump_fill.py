#!/usr/bin/env python3
"""Zero fills in linked code, read from `objdump -d --no-show-raw-insn`.

Imported by both fixture-loop checkers -- check-gcc-fixture-loop.py beside it,
and ../../llvm-repair/scripts/check-fixture-loop.py, which imports it from here
rather than copying it -- for the cells whose output is linked code (a shared
object, an executable) rather than a -S listing, which is what the repository's
assembly oracle (compiler/eval/second-vendor/lib/asm-oracle.mjs) reads. It
recognises the oracle's two inline idioms in objdump's spelling, and calls to
memset, and nothing else.

Compiles nothing. `disassemble` runs objdump on one file and returns its text;
`object_kind` reads four bytes and looks for one section name.
"""

import re
import subprocess


def objdump_body(text, fn):
    """The instruction lines of `fn` in `objdump -d` output, or None."""
    lines = text.split("\n")
    head = re.compile(r"^[0-9a-f]+ <" + re.escape(fn) + r">:$")
    for i, l in enumerate(lines):
        if head.match(l):
            body = []
            for x in lines[i + 1:]:
                if not x.strip():
                    break
                body.append(x)
            return body
    return None


_OBJ_SELF_XOR = re.compile(r"^v?(?:pxor|xorps|xorpd)\s+%([xyz]mm\d+),%([xyz]mm\d+)$")
_OBJ_VEC_STORE = re.compile(r"^v?(?:movaps|movups|movapd|movupd|movdqa|movdqu)\s+%([xyz]mm\d+),(\S*\(\S*\))$")
_OBJ_IMM_STORE = re.compile(r"^mov([bwlq])\s+\$0x0,(\S*\(\S*\))$")
_OBJ_MEMSET_CALL = re.compile(r"^call\s+\S+\s+<(?:memset|__memset_chk)(?:@plt)?>$")
_OBJ_WRITES_VEC = re.compile(r",%([xyz]mm\d+)$")


def _instruction(raw):
    """One body line without its address and without objdump's `# <sym>` note."""
    ins = raw.split("\t", 1)[1].strip() if "\t" in raw else raw.strip()
    return re.sub(r"\s+#.*$", "", ins)


def objdump_zero_stores(text, fn):
    """The zero stores in `fn`, read from `objdump -d --no-show-raw-insn`.

    The assembly oracle's two inline idioms, in objdump's spelling: a vector
    register zeroed against itself and then stored to a memory operand (16, 32
    or 64 bytes by register width), and an immediate zero stored to a memory
    operand (by suffix), plus calls to memset / __memset_chk. A vector register
    that is written by anything else stops counting as zeroed. None when the
    function is not in the output."""
    body = objdump_body(text, fn)
    if body is None:
        return None
    zeroed, stores, calls, nbytes = set(), [], [], 0
    for raw in body:
        ins = _instruction(raw)
        m = _OBJ_SELF_XOR.match(ins)
        if m and m.group(1) == m.group(2):
            zeroed.add(m.group(1))
            continue
        m = _OBJ_VEC_STORE.match(ins)
        if m and m.group(1) in zeroed:
            stores.append(ins)
            nbytes += {"x": 16, "y": 32, "z": 64}[m.group(1)[0]]
            continue
        m = _OBJ_IMM_STORE.match(ins)
        if m:
            stores.append(ins)
            nbytes += {"b": 1, "w": 2, "l": 4, "q": 8}[m.group(1)]
            continue
        if _OBJ_MEMSET_CALL.match(ins):
            calls.append(ins)
            continue
        m = _OBJ_WRITES_VEC.search(ins)
        if m:
            zeroed.discard(m.group(1))
    return {"stores": len(stores), "bytes": nbytes, "calls": len(calls), "lines": stores + calls}


# A direct call or jump to the start of a symbol: `call   1150 <secure_wipe>`,
# `jmp    1030 <memset@plt>`. objdump names the target from the symbol table,
# so a jump inside a function reads `<handle+0x40>` and is not a branch to one.
_OBJ_BRANCH = re.compile(r"^(call|jmp)\s+[0-9a-f]+\s+<([^<>+]+)>$")

MEMSET_SYMBOLS = ("memset", "__memset_chk")


def objdump_branches(text, fn):
    """Every direct call and jump in `fn` to the start of a symbol, as
    (instruction, target) with `@plt` taken off the target. A tail call is a
    jump. None when `fn` is not in the output."""
    body = objdump_body(text, fn)
    if body is None:
        return None
    out = []
    for raw in body:
        ins = _instruction(raw)
        m = _OBJ_BRANCH.match(ins)
        if m:
            target = m.group(2)
            out.append((ins, target[:-4] if target.endswith("@plt") else target))
    return out


def copy_of(target, name):
    """`target` is the function `name`, or a copy of it that a compiler renamed:
    GCC's IPA clones and LTO privatisation (`name.constprop.0`, `name.isra.0`,
    `name.part.0`, `name.lto_priv.0`) and ThinLTO's promotion
    (`name.llvm.<hash>`) keep the name and add a dotted suffix."""
    return target == name or re.fullmatch(re.escape(name) + r"\.[A-Za-z0-9_.]+", target) is not None


def wipe_reading(text, caller, helper, nbytes):
    """Where the zero fill that `caller` asks of `helper(buf, nbytes)` is in a
    linked program, and whether it is there at all.

    Inlined -- no direct call or jump to `helper`, or to a renamed copy of it,
    is left in `caller` -- the fill can only be in `caller` itself. Not inlined,
    it is wherever the copy of `helper` that `caller` branches to does it. In
    that one function: PRESENT when its zero stores cover exactly `nbytes` or it
    calls or tail-calls memset / __memset_chk, ABSENT when it has no zero store
    and no such call, PARTIAL for anything else. NOT_OBSERVED when `caller`, or
    the function it branches to, is not in the output (a helper reached through
    the PLT is in another object, and is not read). With `helper` None the fill
    is `caller`'s own, and `inlined` is None: there is nothing to inline."""
    branches = objdump_branches(text, caller)
    if branches is None:
        return {"verdict": "NOT_OBSERVED", "inlined": None, "where": caller, "bytes": 0, "stores": 0,
                "memsetCalls": 0, "helperCalls": [], "lines": [], "why": f"{caller} is not in the output"}
    to_helper = [(ins, t) for ins, t in branches if helper is not None and copy_of(t, helper)]
    inlined = None if helper is None else not to_helper
    where = to_helper[0][1] if to_helper else caller
    z = objdump_zero_stores(text, where)
    wb = objdump_branches(text, where)
    if z is None or wb is None:
        return {"verdict": "NOT_OBSERVED", "inlined": inlined, "where": where, "bytes": 0, "stores": 0,
                "memsetCalls": 0, "helperCalls": [ins for ins, _ in to_helper], "lines": [],
                "why": f"{where} is not in the output"}
    memset = [ins for ins, t in wb if t in MEMSET_SYMBOLS]
    if z["bytes"] == nbytes or memset:
        verdict = "PRESENT"
    elif z["bytes"] == 0:
        verdict = "ABSENT"
    else:
        verdict = "PARTIAL"
    return {"verdict": verdict, "inlined": inlined, "where": where, "bytes": z["bytes"], "stores": z["stores"],
            "memsetCalls": len(memset), "helperCalls": [ins for ins, _ in to_helper],
            "lines": [l for l in z["lines"] if l not in memset] + memset, "why": None}


def describe(reading):
    """One table cell for a reading: `PRESENT in handle (2 stores/32B)`."""
    if reading["verdict"] == "NOT_OBSERVED":
        return f"NOT_OBSERVED ({reading['why']})"
    what = f"{reading['stores']} store(s)/{reading['bytes']}B"
    if reading["memsetCalls"]:
        what += f"/{reading['memsetCalls']} memset call(s)"
    return f"{reading['verdict']} in {reading['where']} ({what})"


def reading_problems(subject, control, want_inlined, want_subject, caller, helper):
    """What is wrong with the readings of one executable, against what its cell
    expects: `subject` is the wipe `caller` asks of `helper`, `control` a fill
    that cannot be removed, read in the same executable. The control must be
    PRESENT; a cell in which the helper was not inlined where inlining is the
    point says so, rather than reading as a wipe that survived."""
    bad = []
    if subject["verdict"] == "NOT_OBSERVED":
        return [f"subject: {subject['why']}: the executable cannot be read for this cell"]
    if subject["inlined"] is not want_inlined:
        if want_inlined:
            bad.append(f"{helper} was not inlined into {caller} ({subject['helperCalls']} left): this cell "
                       "cannot show a loss that inlining creates, nor a pin that survives one")
        else:
            bad.append(f"{helper} was inlined into {caller}: the helper was not opaque to its caller here, "
                       "so this cell is not the case without the loss")
    if subject["verdict"] != want_subject:
        bad.append(f"subject {describe(subject)}, expected {want_subject}")
    if control["verdict"] != "PRESENT":
        bad.append(f"control {describe(control)}: the reading is blind in this executable")
    return bad


def disassemble(path, objdump="objdump", timeout=120):
    """The text of `objdump -d --no-show-raw-insn <path>`. Raises RuntimeError,
    with a message that carries no path, when there is none."""
    try:
        out = subprocess.run([objdump, "-d", "--no-show-raw-insn", path], capture_output=True,
                             encoding="utf-8", errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"objdump could not run: {e.__class__.__name__}")
    if out.returncode != 0:
        raise RuntimeError(f"objdump exited {out.returncode}")
    return out.stdout


def objdump_version(objdump="objdump"):
    try:
        out = subprocess.run([objdump, "--version"], capture_output=True, encoding="utf-8",
                             errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "objdump: not runnable"
    return (out.stdout.split("\n") or [""])[0]


def object_kind(path):
    """`bitcode` (LLVM bitcode magic), `gcc-lto` (an ELF object carrying GCC's
    .gnu.lto_ sections: an -flto object), `elf` (any other ELF file), `other`,
    or None when the file cannot be read."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if data[:4] == b"BC\xc0\xde":
        return "bitcode"
    if data[:4] == b"\x7fELF":
        return "gcc-lto" if b".gnu.lto_" in data else "elf"
    return "other"
