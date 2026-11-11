/**
 * A reading of zero writes in an x86-64 AT&T listing (clang's or gcc's `-S`)
 * that counts the forms the other readings leave out. Pure functions: nothing
 * here compiles, reads a file or looks at a directory. The tests
 * (../../test/asm-zero-writes.test.mjs) reach all of it with no compiler.
 *
 * Why it exists. asm-oracle's detectInlineZeroStore (../../../second-vendor/
 * lib/asm-oracle.mjs) counts an immediate zero stored to memory and a vector
 * register zeroed against itself and then stored. Three forms were read by hand
 * in listings it calls ABSENT, or calls the same in w and wo:
 *
 *   - a general-purpose register zeroed and then stored: gcc-13 at -O2 writes
 *     a repaired 2-byte copy as `xorl %eax, %eax; movw %ax, 6(%rsp)`, and at
 *     -Os a pinpad initialiser as `xorl %edi, %edi; ...; movl %edi, 1(%rsp);
 *     movl %edi, 4(%rsp)`; clang-18 at -Os writes the same initialiser as
 *     `xorl %eax, %eax; leaq 8(%rsp), %rbx; movl %eax, 3(%rbx); movl %eax,
 *     (%rbx)` (gcc-repair/README.md and repair-loop/README.md, "A third
 *     reading");
 *   - a register given zero by `movl $0, %eax` and then stored (gcc-13 at -O0:
 *     `movl $0, %eax; movq %rax, -16(%rbp)`);
 *   - `rep stos` with a zero accumulator, which zero-delta.mjs keeps beside its
 *     count and never adds to it.
 *
 * This reading counts, per function:
 *
 *   imm       `mov[bwlq] $0, <mem>`
 *   and-imm   `and[bwlq] $0, <mem>` (a read-modify-write that leaves zero)
 *   zero-gpr  a store of a general-purpose register known to hold zero
 *   zero-vec  a store of a vector register known to hold zero
 *   rep-stos  `rep stos[bwlq]` (or a single `stos`) whose accumulator is zero
 *
 * A register is known to hold zero after `xor`/`sub` of itself, `mov $0` or
 * `and $0` into it, `(v)pxor`/`(v)xorps`/`(v)xorpd`/`vpxor[dq]`/`(v)psub*` of a
 * register with itself (the three-operand VEX form when both sources are the
 * same register), or a register-to-register copy (`mov`, `movz*`, `movs*`
 * extensions, vector register moves, `movd`/`movq` into a vector register) of a
 * register that holds zero. Widths are tracked: a 32- or 64-bit write zeroes
 * the whole 64-bit register; an 8- or 16-bit write zeroes only what it writes;
 * a legacy SSE write zeroes 16 bytes and leaves the rest of the vector register
 * as it was; a VEX or EVEX write zeroes the whole register. A store counts only
 * when every byte it stores is known to be zero (`xorw %ax, %ax; movl %eax,
 * (%rsp)` is not counted).
 *
 * The knowledge is dropped:
 *
 *   - for a register, at any instruction that writes it: its last operand (AT&T
 *     order), both operands of `xchg`/`xadd`, and the implicit writes listed in
 *     IMPLICIT below (mul/div, cltq/cqto, cpuid, rdtsc, syscall, the string
 *     instructions, leave, cmpxchg, pop, ...);
 *   - for the caller-saved registers (rax rcx rdx rsi rdi r8-r11 and every
 *     vector register), at a `call` -- the callee-saved ones survive it, as the
 *     System V ABI says;
 *   - for every register, at a label (the start of a basic block) and after a
 *     jump or a return (scope 'block', the default). With scope 'fallthrough',
 *     a conditional jump keeps it: the unlabelled instruction after a `jcc` can
 *     only be reached from the `jcc`'s own block. With scope 'function', a
 *     block starts with what every predecessor it can see (fall-through and
 *     direct jumps) agrees on, computed to a fixed point over the body (loops
 *     included); a block that something else may reach -- the entry, a block
 *     with no predecessor it can see (an unwinder's landing pad), a label
 *     named by a jump table or anywhere else in the listing, every labelled
 *     block of a body with an indirect jump -- starts with nothing known.
 *     Measured 2026-11-11 in the lab on the r2 listings without a plugin
 *     (clang-18 and gcc-13, every level, 3,200 bodies each, listings that
 *     zero-delta.mjs --corpus wrote): asm-oracle counts an inline zero store that
 *     scope 'block' does not in 7 clang-18 and 2 gcc-13 bodies. Scope
 *     'function' counts all of them in 6 and 2. In the seventh
 *     (sonnet_S_pwverify_r3 at -O3) the 23 stores left are spills of %xmm0
 *     right after it was loaded from memory (`movss 12(%rsp), %xmm0`) or
 *     shuffled (`punpcklwd`): detectInlineZeroStore never forgets a register
 *     it once saw zeroed, and they are not zero writes.
 *
 * Where a write lands. A memory operand `N(%rsp)` or `N(%rbp)` with no index
 * is read as frame base and offset as written. A base register set in the same
 * scope by `leaq K(%rsp), %rB` (or `movq %rsp, %rB`, or `leaq K(%rbp), %rB`,
 * or copied from such a register, or moved by `add`/`sub` of an immediate) is
 * re-based: `movl %eax, 3(%rbx)` after `leaq 8(%rsp), %rbx` is 11(%rsp). Any
 * write to %rsp (sub, add, push, pop, leave, ...) forgets the registers based
 * on it; the offsets are never corrected for a moved %rsp. Any other memory
 * operand keeps its base register's name and an offset only when it has no
 * index; a symbol (`key(%rip)`) keeps the symbol.
 *
 * What it does not see, and does not guess at: a zero held in a register set
 * in an earlier block (scope 'block'; scope 'function' sees it when every
 * path agrees), a register zeroed by an instruction not listed above, a call
 * or a tail call to any function (memset, explicit_bzero,
 * __explicit_bzero_chk; observeEffect reads calls), an indirect call, AVX-512
 * masked stores (`{%k1}`), `rep stos`
 * whose count or destination is not set in the same scope (it is counted, with
 * bytes null). A zero write is not a wipe: an initialiser is a zero write too,
 * and nothing here reads position.
 */

// ---------------------------------------------------------------- registers --

const GPR = new Map();
for (const [q, l, w, b, h] of [['rax', 'eax', 'ax', 'al', 'ah'], ['rbx', 'ebx', 'bx', 'bl', 'bh'],
  ['rcx', 'ecx', 'cx', 'cl', 'ch'], ['rdx', 'edx', 'dx', 'dl', 'dh']]) {
  GPR.set(q, { fam: q, width: 8 }).set(l, { fam: q, width: 4 }).set(w, { fam: q, width: 2 })
    .set(b, { fam: q, width: 1 }).set(h, { fam: q, width: 1, high: true });
}
for (const [q, l, w, b] of [['rsi', 'esi', 'si', 'sil'], ['rdi', 'edi', 'di', 'dil'],
  ['rbp', 'ebp', 'bp', 'bpl'], ['rsp', 'esp', 'sp', 'spl']]) {
  GPR.set(q, { fam: q, width: 8 }).set(l, { fam: q, width: 4 }).set(w, { fam: q, width: 2 }).set(b, { fam: q, width: 1 });
}
for (let n = 8; n <= 15; n++) {
  const q = `r${n}`;
  GPR.set(q, { fam: q, width: 8 }).set(`${q}d`, { fam: q, width: 4 }).set(`${q}w`, { fam: q, width: 2 })
    .set(`${q}b`, { fam: q, width: 1 }).set(`${q}l`, { fam: q, width: 1 });
}

/** The System V caller-saved general-purpose registers; every vector register is caller-saved too. */
export const CALLER_SAVED = new Set(['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']);

/**
 * A register operand: {name, fam, width, gpr|vec|other, high?}, or null when
 * the operand is not a bare register. `fam` is the 64-bit name for a GPR,
 * `v<N>` for xmm/ymm/zmm N, and the name itself for anything else (%k1, %st).
 */
export function regOf(op) {
  const m = /^%([a-z][a-z0-9]*)$/.exec(op ?? '');
  if (!m) return null;
  const name = m[1];
  const g = GPR.get(name);
  if (g) return { name, fam: g.fam, width: g.width, gpr: true, high: !!g.high };
  const v = /^([xyz])mm(\d+)$/.exec(name);
  if (v) return { name, fam: `v${v[2]}`, width: { x: 16, y: 32, z: 64 }[v[1]], vec: true };
  return { name, fam: name, width: null, other: true };
}

/** A memory operand: anything not a register, not an immediate and not a `*` target. */
export function isMem(op) {
  if (typeof op !== 'string' || !op) return false;
  if (op.startsWith('$') || op.startsWith('*')) return false;
  if (/^%[cdefgs]s:/.test(op)) return true;
  return !op.startsWith('%');
}

/**
 * The parts of a memory operand: {disp, sym, base, index, scale}. `disp` is a
 * number (0 when absent) or null when the displacement is symbolic; `sym` is
 * the symbolic part. null when the operand does not parse.
 */
export function addrOf(op) {
  const s = op.replace(/^%[cdefgs]s:/, '');
  const m = /^([^()]*)\((%[a-z0-9]+)?(?:,(%[a-z0-9]+)(?:,(\d+))?)?\)$/.exec(s);
  if (!m) {
    // a bare symbol or absolute address
    if (/^[^()%$\s]+$/.test(s)) return { disp: /^-?(0x[0-9a-f]+|\d+)$/i.test(s) ? Number(s) : null, sym: s, base: null, index: null, scale: null };
    return null;
  }
  const d = m[1].trim();
  let disp = 0, sym = null;
  if (d !== '') {
    if (/^-?(0x[0-9a-f]+|\d+)$/i.test(d)) disp = d.startsWith('-') ? -Number(d.slice(1)) : Number(d);
    else { disp = null; sym = d; }
  }
  return { disp, sym, base: m[2] ? m[2].slice(1) : null, index: m[3] ? m[3].slice(1) : null, scale: m[4] ? Number(m[4]) : null };
}

// ------------------------------------------------------------- instructions --

const PREFIXES = new Set(['rep', 'repe', 'repz', 'repne', 'repnz', 'lock', 'notrack', 'data16', 'data32',
  'addr32', 'cs', 'ds', 'es', 'ss', 'fs', 'gs', 'rex', 'rex64', 'bnd', 'xacquire', 'xrelease']);

/** Split an operand list on the commas outside parentheses and braces. */
export function splitOperands(s) {
  const out = [];
  let depth = 0, cur = '';
  for (const ch of s) {
    if (ch === '(' || ch === '{') depth++;
    else if (ch === ')' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; } else cur += ch;
  }
  if (cur.trim() !== '') out.push(cur.trim());
  return out;
}

/** Strip the `#` comment, as asm-oracle does for both vendors on x86-64 ELF. */
const stripComment = (line) => {
  const i = line.indexOf('#');
  return (i === -1 ? line : line.slice(0, i)).trimEnd();
};

/**
 * One source line as a list of items: {kind: 'label', name} | {kind: 'insn',
 * mnem, ops, prefixes} | {kind: 'directive'}; [] for a blank or comment line.
 * A `;` separates instructions (`rep; stosq`), and a prefix alone carries to
 * the next.
 */
export function parseLine(raw) {
  const line = stripComment(raw);
  if (line.trim() === '') return [];
  const lab = /^([^\s:"]+):\s*$/.exec(line);
  if (lab && !/^\s/.test(line)) return [{ kind: 'label', name: lab[1] }];
  const t = line.trim();
  if (t.startsWith('.')) return [{ kind: 'directive' }];
  const items = [];
  let carry = [];
  for (const seg of t.split(';').map((x) => x.trim()).filter(Boolean)) {
    let rest = seg;
    const prefixes = [...carry];
    carry = [];
    for (;;) {
      const m = /^([a-z][a-z0-9.]*)(?:\s+(.*))?$/i.exec(rest);
      if (!m) { rest = null; break; }
      if (PREFIXES.has(m[1].toLowerCase()) ) {
        prefixes.push(m[1].toLowerCase());
        if (m[2] === undefined) { rest = ''; break; }
        rest = m[2];
        continue;
      }
      items.push({ kind: 'insn', mnem: m[1].toLowerCase(), ops: m[2] ? splitOperands(m[2]) : [], prefixes });
      rest = null;
      break;
    }
    if (rest === '') carry = prefixes;
  }
  return items;
}

const NO_WRITE = /^(cmp[bwlq]?|test[bwlq]?|bt[wlq]?|v?u?comis[sd]|v?ptest|push[wlq]?|nop[wlq]?|prefetch\w*|clflush\w*|[lms]fence|pause|endbr(32|64))$/;
const JUMP = /^(jmp[lq]?|j(a|ae|b|be|c|cxz|e|ecxz|rcxz|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)|loop(e|ne|z|nz)?)$/;
const UNCOND = /^(jmp[lq]?|ret[lqw]?|ud2|hlt)$/;
const RET = /^(ret[lqw]?|ud2|hlt)$/;
const CALL = /^call[lq]?$/;
const STRING = /^(stos|lods|scas|movs|cmps)([bwlq])?$/;
const ELEM = { b: 1, w: 2, l: 4, q: 8 };

/** Implicit register writes, beyond the last operand (AT&T order). */
export const IMPLICIT = [
  [/^(mul|div|idiv)[bwlq]?$/, ['rax', 'rdx']],
  [/^(cltq|cdqe|cwtl|cwde|cbtw|cbw)$/, ['rax']],
  [/^(cqto|cqo|cltd|cdq|cwtd|cwd)$/, ['rdx']],
  [/^cpuid$/, ['rax', 'rbx', 'rcx', 'rdx']],
  [/^rdtscp?$/, ['rax', 'rcx', 'rdx']],
  [/^(xgetbv|rdpmc|rdmsr)$/, ['rax', 'rdx']],
  [/^(syscall|sysenter)$/, ['rax', 'rcx', 'r11']],
  [/^lahf$/, ['rax']],
  [/^(leave|enter)[wlq]?$/, ['rbp', 'rsp']],
  [/^cmpxchg[bwlq]?$/, ['rax']],
  [/^cmpxchg(8b|16b)$/, ['rax', 'rdx']],
  [/^xlatb?$/, ['rax']],
  [/^loop(e|ne|z|nz)?$/, ['rcx']],
  [/^(push|pop)[wlq]?$/, ['rsp']],
];

/** The general-purpose and vector families an instruction writes, besides a zero it makes. */
function writtenFamilies(mnem, ops) {
  const fams = new Set();
  if (NO_WRITE.test(mnem) || JUMP.test(mnem) || RET.test(mnem)) {
    if (/^push/.test(mnem)) fams.add('rsp');
    return fams;
  }
  if (CALL.test(mnem)) return fams; // handled by the caller (clobbers, not writes)
  const s = STRING.exec(mnem);
  if (s && !ops.some((o) => regOf(o)?.vec)) { for (const f of ['rcx', 'rdi', 'rsi', 'rax']) fams.add(f); return fams; }
  for (const [re, list] of IMPLICIT) if (re.test(mnem)) for (const f of list) fams.add(f);
  if (/^(i?mul|div|idiv)[bwlq]?$/.test(mnem) && ops.length === 1) { fams.add('rax'); fams.add('rdx'); return fams; }
  if (/^(xchg|xadd)[bwlq]?$/.test(mnem)) for (const o of ops) { const r = regOf(o); if (r) fams.add(r.fam); }
  if (ops.length) {
    const last = ops[ops.length - 1];
    const r = regOf(last.replace(/\s*\{.*$/, ''));
    if (r) fams.add(r.fam);
  }
  return fams;
}

const isZeroImm = (op) => /^\$(-?0|0x0+)$/i.test(op ?? '');
const constImm = (op) => {
  const m = /^\$(-?)(0x[0-9a-f]+|\d+)$/i.exec(op ?? '');
  return m ? (m[1] ? -1 : 1) * Number(m[2]) : null;
};

const VEC_FULL = /^v?mov(aps|ups|apd|upd|dqa|dqu|ntps|ntpd|ntdq)$|^vmov(dqa32|dqa64|dqu8|dqu16|dqu32|dqu64)$/;
const VEC_HALF = /^v?mov(lps|lpd|hps|hpd)$/;
const VEC_ZERO2 = /^(pxor|xorps|xorpd|psubb|psubw|psubd|psubq)$/;
const VEC_ZERO3 = /^(vpxor|vxorps|vxorpd|vpxord|vpxorq|vpsubb|vpsubw|vpsubd|vpsubq)$/;
const GPR_ZERO_SELF = /^(xor|sub)([bwlq])?$/;
const EXTEND = /^(movz|movs)(b[wlq]|w[lq]|lq)$|^movzx$|^movsx[d]?$/;

// ------------------------------------------------------------------- blocks --

/**
 * Labels that mark a place for the debug information or the unwind tables and
 * are never a branch target in compiler output: gcc's `.LVL<n>`, `.LFB<n>`,
 * `.LFE<n>`, `.LCFI<n>`, `.LBB<n>`/`.LBE<n>` (lexical blocks; clang's basic
 * blocks are `.LBB<f>_<n>`, with the underscore), `.LBI<n>`, `.LEHB<n>`/
 * `.LEHE<n>` (call-site ranges), and clang's `.Ltmp<n>`, `.Lfunc_begin<n>`,
 * `.Lfunc_end<n>`. With `-g` gcc puts a `.LVL` label between most
 * instructions; reading each as a block boundary would forget every zero
 * register. Any other label is a boundary, and so is one of these when a jump
 * in the same body names it.
 */
export const NON_BLOCK_LABEL = /^\.(LVL\d+|LFB\d+|LFE\d+|LCFI\d+|LBB\d+|LBE\d+|LBI\d+|LEHB\d+|LEHE\d+|Ltmp\d+|Lfunc_begin\d+|Lfunc_end\d+)$/;

/** The labels a jump or a loop instruction in these lines names. */
export function jumpTargets(lines) {
  const out = new Set();
  for (const raw of lines) {
    for (const it of parseLine(raw)) {
      if (it.kind === 'insn' && JUMP.test(it.mnem) && it.ops.length === 1 && !it.ops[0].startsWith('*')) out.add(it.ops[0]);
    }
  }
  return out;
}

export function isBlockLabel(name, targets = new Set()) {
  return !NON_BLOCK_LABEL.test(name) || targets.has(name);
}

// --------------------------------------------------------------------- state --

function freshState() {
  // zero: fam -> low bytes known zero; addr: fam -> {base, off}; konst: fam -> value; at: fam -> line that made it zero
  return { zero: new Map(), addr: new Map(), konst: new Map(), at: new Map() };
}

function cloneState(st) {
  return { zero: new Map(st.zero), addr: new Map([...st.addr].map(([k, v]) => [k, { ...v }])), konst: new Map(st.konst), at: new Map(st.at) };
}

const sameMap = (a, b, eq = (x, y) => x === y) => a.size === b.size && [...a].every(([k, v]) => b.has(k) && eq(v, b.get(k)));
const sameState = (a, b) => sameMap(a.zero, b.zero) && sameMap(a.konst, b.konst) && sameMap(a.at, b.at)
  && sameMap(a.addr, b.addr, (x, y) => x.base === y.base && x.off === y.off);

/**
 * What every incoming state agrees on, at a join: a register is zero in the
 * low bytes all of them have zero, a base or a constant only when all agree.
 */
export function meetStates(states) {
  if (!states.length) return freshState();
  const [a, ...rest] = states;
  const out = cloneState(a);
  for (const s of rest) {
    for (const [f, z] of [...out.zero]) { const y = s.zero.get(f); if (y === undefined) out.zero.delete(f); else out.zero.set(f, Math.min(z, y)); }
    for (const [f, t] of [...out.addr]) { const u = s.addr.get(f); if (!u || u.base !== t.base || u.off !== t.off) out.addr.delete(f); }
    for (const [f, k] of [...out.konst]) if (s.konst.get(f) !== k) out.konst.delete(f);
    for (const [f, l] of [...out.at]) if (s.at.get(f) !== l) out.at.set(f, null);
  }
  for (const f of [...out.at.keys()]) if (!out.zero.has(f)) out.at.delete(f);
  return out;
}

/** Record a write of `reg`; `isZero` when the value written is zero, `vex` for a VEX/EVEX vector write. */
function setReg(st, reg, isZero, vex) {
  st.addr.delete(reg.fam);
  st.konst.delete(reg.fam);
  st.at.delete(reg.fam);
  if (reg.fam === 'rsp' || reg.fam === 'rbp') for (const [f, a] of [...st.addr]) if (a.base === reg.fam) st.addr.delete(f);
  if (reg.other) { st.zero.delete(reg.fam); return; }
  const prev = st.zero.get(reg.fam) ?? 0;
  if (reg.vec) {
    if (vex) { if (isZero) st.zero.set(reg.fam, 64); else st.zero.delete(reg.fam); }
    else if (isZero) st.zero.set(reg.fam, Math.max(prev, 16));
    else st.zero.delete(reg.fam);
    return;
  }
  if (reg.width >= 4) {
    if (isZero) { st.zero.set(reg.fam, 8); st.konst.set(reg.fam, 0); } else st.zero.delete(reg.fam);
  } else if (reg.high) {
    if (!(isZero && prev >= 2)) st.zero.delete(reg.fam);
  } else if (isZero) st.zero.set(reg.fam, Math.max(prev, reg.width));
  else st.zero.delete(reg.fam);
}

/** Does `reg` hold zero in every byte a store of `bytes` from it would write? */
function holdsZero(st, reg, bytes) {
  const z = st.zero.get(reg.fam) ?? 0;
  if (reg.high) return z >= 2;
  return z >= bytes;
}

function forgetFamilies(st, fams) {
  for (const f of fams) { st.zero.delete(f); st.addr.delete(f); st.konst.delete(f); st.at.delete(f); }
  if (fams.has('rsp')) for (const [f, a] of [...st.addr]) if (a.base === 'rsp') st.addr.delete(f);
  if (fams.has('rbp')) for (const [f, a] of [...st.addr]) if (a.base === 'rbp') st.addr.delete(f);
}

/** Where a memory destination lands: {dest, base, offset, via}. */
function locate(st, op) {
  const a = addrOf(op);
  if (!a) return { dest: op, base: null, offset: null, via: null };
  if (a.base === 'rip' || (a.base === null && a.sym)) return { dest: op, base: a.sym ?? 'rip', offset: null, via: null };
  if (a.base && !a.index && a.disp !== null) {
    const fam = GPR.get(a.base)?.fam ?? a.base;
    if (fam === 'rsp' || fam === 'rbp') return { dest: op, base: fam, offset: a.disp, via: null };
    const t = st.addr.get(fam);
    if (t) return { dest: op, base: t.base, offset: t.off + a.disp, via: fam };
    return { dest: op, base: fam, offset: a.disp, via: null };
  }
  return { dest: op, base: a.base ? (GPR.get(a.base)?.fam ?? a.base) : null, offset: null, via: null };
}

// ------------------------------------------------------------------ reading --

/**
 * One instruction's effect on `st`; a zero write it makes goes to `push`.
 * Returns 'uncond' or 'cond' for a jump or a return (the state is left as it
 * is; the caller decides what a block end forgets), null otherwise.
 */
function step(st, it, lineNo, raw, push) {
  const { mnem, ops, prefixes } = it;
  const text = stripComment(raw).trim();
  const masked = ops.some((o) => o.includes('{'));
  const emit = (w) => push({ line: lineNo, text, ...w });
  const zeroAt = (fam, line) => { st.at.set(fam, line); };

  // control transfer
  if (CALL.test(mnem)) {
    const fams = new Set([...CALLER_SAVED]);
    for (const f of [...st.zero.keys(), ...st.addr.keys(), ...st.konst.keys()]) if (f.startsWith('v')) fams.add(f);
    forgetFamilies(st, fams);
    return null;
  }
  if (JUMP.test(mnem) || RET.test(mnem)) {
    if (/^loop/.test(mnem)) forgetFamilies(st, new Set(['rcx']));
    return UNCOND.test(mnem) ? 'uncond' : 'cond';
  }

  // rep stos / stos
  const s = STRING.exec(mnem);
  if (s && s[1] === 'stos' && !masked) {
    const accOp = ops.length === 2 ? regOf(ops[0]) : null;
    const elem = s[2] ? ELEM[s[2]] : accOp?.width ?? null;
    const acc = accOp ?? { fam: 'rax', width: elem, gpr: true };
    const rep = prefixes.some((p) => p.startsWith('rep'));
    if (elem && holdsZero(st, acc, elem)) {
      const count = rep ? st.konst.get('rcx') : 1;
      const t = st.addr.get('rdi');
      emit({ form: 'rep-stos', bytes: typeof count === 'number' ? count * elem : null,
        dest: '(%rdi)', base: t ? t.base : 'rdi', offset: t ? t.off : null, via: t ? 'rdi' : null,
        reg: `%${acc.name ?? 'rax'}`, zeroedAt: st.at.get('rax') ?? null });
    }
    forgetFamilies(st, new Set(['rcx', 'rdi']));
    return null;
  }
  if (s && !ops.some((o) => regOf(o)?.vec)) { forgetFamilies(st, writtenFamilies(mnem, ops)); return null; }

  const src = ops[0], dst = ops[ops.length - 1];
  const rs = ops.length >= 2 ? regOf(src) : null;
  const rd = ops.length >= 1 ? regOf(dst) : null;
  const vex = mnem.startsWith('v');

  // stores to memory
  if (ops.length === 2 && isMem(dst) && !masked) {
    let w = null;
    const mg = /^mov([bwlq])?$/.exec(mnem);
    const ma = /^and([bwlq])$/.exec(mnem);
    if (mg && isZeroImm(src) && mg[1]) w = { form: 'imm', bytes: ELEM[mg[1]] };
    else if (ma && isZeroImm(src)) w = { form: 'and-imm', bytes: ELEM[ma[1]] };
    else if (rs?.gpr && (mg || mnem === 'movnti' || /^movnti[lq]$/.test(mnem))) {
      if (holdsZero(st, rs, rs.width)) w = { form: 'zero-gpr', bytes: rs.width, reg: `%${rs.name}`, zeroedAt: st.at.get(rs.fam) ?? null };
    } else if (rs?.vec) {
      let bytes = null, need = null;
      if (VEC_FULL.test(mnem)) { bytes = rs.width; need = rs.width; }
      else if (VEC_HALF.test(mnem)) { bytes = 8; need = /h(ps|pd)$/.test(mnem) ? 16 : 8; }
      else if (/^v?movq$/.test(mnem) || /^v?movsd$/.test(mnem)) { bytes = 8; need = 8; }
      else if (/^v?movd$/.test(mnem) || /^v?movss$/.test(mnem)) { bytes = 4; need = 4; }
      if (bytes !== null && (st.zero.get(rs.fam) ?? 0) >= need) {
        w = { form: 'zero-vec', bytes, reg: `%${rs.name}`, zeroedAt: st.at.get(rs.fam) ?? null };
      }
    }
    if (w) emit({ ...w, ...locate(st, dst) });
    // a store writes no register (cmpxchg/xchg/xadd with a memory operand still write theirs)
    if (/^(xchg|xadd|cmpxchg)/.test(mnem)) forgetFamilies(st, writtenFamilies(mnem, ops));
    return null;
  }

  // a register made zero, a register copied, a frame address taken
  if (rd && !masked) {
    // xor/sub of itself
    const gz = GPR_ZERO_SELF.exec(mnem);
    if (gz && ops.length === 2 && rs?.gpr && rd.gpr && rs.name === rd.name) {
      setReg(st, rd, true, false); zeroAt(rd.fam, lineNo); return null;
    }
    // mov/and $0 into a register
    if ((/^mov([bwlq])?$|^movabsq$/.test(mnem) || /^and([bwlq])?$/.test(mnem)) && ops.length === 2 && isZeroImm(src) && rd.gpr) {
      setReg(st, rd, true, false); zeroAt(rd.fam, lineNo); return null;
    }
    // mov $N into a register: a constant (rep stos's count)
    if (/^mov([lq])?$|^movabsq$/.test(mnem) && ops.length === 2 && rd.gpr && rd.width >= 4 && constImm(src) !== null) {
      setReg(st, rd, false, false); st.konst.set(rd.fam, constImm(src)); return null;
    }
    // vector zero idioms
    if (VEC_ZERO2.test(mnem) && ops.length === 2 && rs?.vec && rd.vec && rs.name === rd.name) {
      setReg(st, rd, true, false); zeroAt(rd.fam, lineNo); return null;
    }
    if (VEC_ZERO3.test(mnem) && ops.length === 3) {
      const a = regOf(ops[0]), b = regOf(ops[1]);
      if (a?.vec && b?.vec && a.fam === b.fam && rd.vec) { setReg(st, rd, true, true); zeroAt(rd.fam, lineNo); return null; }
    }
    if (VEC_ZERO2.test(mnem) && vex === false && ops.length === 2 && rd.vec) { setReg(st, rd, false, false); return null; }
    // frame addresses
    if (/^lea[lq]?$/.test(mnem) && ops.length === 2 && rd.gpr && rd.width === 8) {
      const a = addrOf(src);
      const bf = a?.base ? GPR.get(a.base)?.fam : null;
      const t = bf ? st.addr.get(bf) : null;
      setReg(st, rd, false, false);
      if (a && !a.index && a.disp !== null && (bf === 'rsp' || bf === 'rbp') && rd.fam !== bf) st.addr.set(rd.fam, { base: bf, off: a.disp });
      else if (a && !a.index && a.disp !== null && t) st.addr.set(rd.fam, { base: t.base, off: t.off + a.disp });
      return null;
    }
    // add/sub of an immediate to a frame-based register
    if (/^(add|sub)q?$/.test(mnem) && ops.length === 2 && rd.gpr && rd.width === 8 && constImm(src) !== null
      && rd.fam !== 'rsp' && rd.fam !== 'rbp' && st.addr.has(rd.fam)) {
      const t = st.addr.get(rd.fam);
      const k = constImm(src) * (mnem.startsWith('add') ? 1 : -1);
      setReg(st, rd, false, false);
      st.addr.set(rd.fam, { base: t.base, off: t.off + k });
      return null;
    }
    // register-to-register copies
    if (rs && ops.length === 2) {
      const copy = /^mov([lq])?$/.test(mnem) && rs.gpr && rd.gpr && rs.width === rd.width && rd.width >= 4;
      const ext = EXTEND.test(mnem) && rs.gpr && rd.gpr;
      const vcopy = (VEC_FULL.test(mnem) || /^v?movap[sd]$|^v?movdq[au]$/.test(mnem)) && rs.vec && rd.vec;
      const toVec = /^v?mov[dq]$/.test(mnem) && rs.gpr && rd.vec;
      const fromVec = /^v?mov[dq]$/.test(mnem) && rs.vec && rd.gpr;
      const srcAt = st.at.get(rs.fam) ?? lineNo;
      if (copy || ext) {
        const z = holdsZero(st, rs, rs.width);
        const t = copy && rd.width === 8 ? st.addr.get(rs.fam) : null;
        const fromRsp = copy && rd.width === 8 && (rs.fam === 'rsp' || rs.fam === 'rbp') && rs.width === 8;
        setReg(st, rd, z, false);
        if (z) zeroAt(rd.fam, srcAt);
        if (t) st.addr.set(rd.fam, { ...t });
        else if (fromRsp) st.addr.set(rd.fam, { base: rs.fam, off: 0 });
        if (rd.fam === 'rsp' || rd.fam === 'rbp') forgetFamilies(st, new Set([rd.fam]));
        return null;
      }
      if (vcopy || toVec) {
        const need = toVec ? (/d$/.test(mnem) ? 4 : 8) : rs.width;
        const z = holdsZero(st, rs, need);
        setReg(st, rd, z, vex);
        if (z) zeroAt(rd.fam, srcAt);
        return null;
      }
      if (fromVec) {
        const need = /d$/.test(mnem) ? 4 : 8;
        const z = (st.zero.get(rs.fam) ?? 0) >= need;
        setReg(st, rd, z, false);
        if (z) zeroAt(rd.fam, srcAt);
        return null;
      }
    }
  }

  // everything else: forget what it writes
  forgetFamilies(st, writtenFamilies(mnem, ops));
  return null;
}

/**
 * Labels named anywhere in `lines` other than as the operand of a direct jump:
 * jump tables (`.quad .LBB0_3`, `.long .L4-.L3`), unwind tables
 * (`.uleb128 .L5-.LFB0`), an address taken with `leaq .L5(%rip)`. Scope
 * 'function' gives a block with such a label no known predecessors.
 */
export function labelsReferenced(lines) {
  const out = new Set();
  for (const raw of lines) {
    const line = stripComment(raw);
    if (/^[^\s:"]+:\s*$/.test(line)) continue;
    const items = parseLine(raw);
    if (items.length === 1 && items[0].kind === 'insn' && JUMP.test(items[0].mnem) && items[0].ops.length === 1) continue;
    for (const m of line.matchAll(/\.L[A-Za-z0-9_$.]+/g)) out.add(m[0]);
  }
  return out;
}

/**
 * The basic blocks of a body, for scope 'function': [{labels, items, end,
 * jumpTo, indirect}] with `items` the instructions ({lineNo, raw, it}).
 */
export function basicBlocks(lines, first = 1) {
  const targets = jumpTargets(lines);
  const blocks = [];
  let cur = null;
  const start = (label) => { cur = { labels: label ? [label] : [], items: [], end: null, jumpTo: [], indirect: false }; blocks.push(cur); };
  start(null);
  lines.forEach((raw, i) => {
    for (const it of parseLine(raw)) {
      if (it.kind === 'label') {
        if (!isBlockLabel(it.name, targets)) continue;
        if (!cur.items.length) cur.labels.push(it.name); else start(it.name);
        continue;
      }
      if (it.kind !== 'insn') continue;
      if (cur.end !== null) start(null);
      cur.items.push({ lineNo: first + i, raw, it });
      if (JUMP.test(it.mnem) || RET.test(it.mnem)) {
        cur.end = UNCOND.test(it.mnem) ? 'uncond' : 'cond';
        const op = it.ops[0];
        if (JUMP.test(it.mnem) && op) { if (op.startsWith('*')) cur.indirect = true; else cur.jumpTo.push(op); }
      }
    }
  });
  return blocks;
}

/**
 * Scope 'function': a forward "must hold zero" analysis over the body's
 * blocks. A block's entry state is what every predecessor's exit state agrees
 * on (meetStates); a block with no known predecessor -- the entry, a block
 * only an unwinder or a jump table reaches, any labelled block of a body
 * with an indirect jump -- starts knowing nothing. Iterated from "everything"
 * down to a fixed point, which is never more than every path guarantees.
 */
function functionScope(lines, first, externalRefs) {
  const blocks = basicBlocks(lines, first);
  const n = blocks.length;
  const at = new Map();
  blocks.forEach((b, i) => b.labels.forEach((l) => at.set(l, i)));
  const preds = blocks.map(() => []);
  blocks.forEach((b, i) => {
    if (b.end !== 'uncond' && i + 1 < n) preds[i + 1].push(i);
    for (const t of b.jumpTo) { const j = at.get(t); if (j !== undefined) preds[j].push(i); }
  });
  const indirect = blocks.some((b) => b.indirect);
  const refs = externalRefs ?? labelsReferenced(lines);
  const unknown = blocks.map((b, i) => i === 0 || !preds[i].length || (indirect && b.labels.length > 0) || b.labels.some((l) => refs.has(l)));
  const run = (st, b, push) => { for (const x of b.items) step(st, x.it, x.lineNo, x.raw, push); return st; };
  const ins = new Array(n), outs = new Array(n);
  const none = () => {};
  for (let pass = 0, changed = true; changed; pass++) {
    if (pass > 10 * n + 10) throw new Error('scope function: no fixed point (this is a bug)');
    changed = false;
    for (let i = 0; i < n; i++) {
      let s;
      if (unknown[i]) s = freshState();
      else {
        const known = preds[i].map((p) => outs[p]).filter(Boolean);
        if (!known.length) continue;
        s = meetStates(known);
      }
      if (ins[i] && sameState(ins[i], s)) continue;
      ins[i] = s;
      outs[i] = run(cloneState(s), blocks[i], none);
      changed = true;
    }
  }
  const writes = [];
  blocks.forEach((b, i) => run(ins[i] ? cloneState(ins[i]) : freshState(), b, (w) => writes.push(w)));
  return writes;
}

/**
 * The zero writes in one body. `lines` are the raw lines of the function (as
 * extractFunctionBody returns them, or any list of listing lines); `first` is
 * the listing line number of lines[0]. Scope 'block' (the default) and
 * 'fallthrough' read the lines in order; scope 'function' carries what is
 * known across blocks (functionScope). `externalRefs`, for scope 'function',
 * is labelsReferenced over the whole listing (readListing and zeroWritesOf
 * pass it); without it only the body's own lines are searched. Returns the
 * writes in listing order.
 */
export function zeroWritesInLines(lines, { scope = 'block', first = 1, externalRefs = null } = {}) {
  if (!['block', 'fallthrough', 'function'].includes(scope)) throw new Error(`scope must be 'block', 'fallthrough' or 'function', not ${JSON.stringify(scope)}`);
  if (scope === 'function') return functionScope(lines, first, externalRefs);
  const targets = jumpTargets(lines);
  let st = freshState();
  const writes = [];
  const push = (w) => writes.push(w);
  lines.forEach((raw, i) => {
    for (const it of parseLine(raw)) {
      if (it.kind === 'label') { if (isBlockLabel(it.name, targets)) st = freshState(); continue; }
      if (it.kind !== 'insn') continue;
      const end = step(st, it, first + i, raw, push);
      if (end === 'uncond' || (end === 'cond' && scope === 'block')) st = freshState();
    }
  });
  return writes;
}

/**
 * Totals over a list of writes: {count, bytes, unknownBytes, byForm, byOffset,
 * distinct}. `bytes` sums the writes whose width is known; `unknownBytes`
 * counts the rest. `byOffset` groups by (base, offset) -- base `rsp`/`rbp` for
 * the frame, a register name or a symbol otherwise, offset null when it is not
 * a constant. `distinct` is, per frame base, the number of distinct bytes the
 * writes with a known offset and width cover (overlaps counted once).
 */
export function summarizeWrites(writes) {
  const byForm = {};
  const groups = new Map();
  const ranges = new Map();
  let bytes = 0, unknownBytes = 0;
  for (const w of writes) {
    const f = (byForm[w.form] ??= { count: 0, bytes: 0, unknownBytes: 0 });
    f.count++;
    if (w.bytes === null) { f.unknownBytes++; unknownBytes++; } else { f.bytes += w.bytes; bytes += w.bytes; }
    const k = `${w.base}\u0000${w.offset}`;
    const g = groups.get(k) ?? { base: w.base, offset: w.offset, count: 0, bytes: 0, unknownBytes: 0 };
    g.count++;
    if (w.bytes === null) g.unknownBytes++; else g.bytes += w.bytes;
    groups.set(k, g);
    if ((w.base === 'rsp' || w.base === 'rbp') && w.offset !== null && w.bytes !== null) {
      const set = ranges.get(w.base) ?? new Set();
      for (let b = w.offset; b < w.offset + w.bytes; b++) set.add(b);
      ranges.set(w.base, set);
    }
  }
  const byOffset = [...groups.values()].sort((a, b) => String(a.base).localeCompare(String(b.base))
    || (a.offset ?? Infinity) - (b.offset ?? Infinity));
  const distinct = Object.fromEntries([...ranges].map(([b, s]) => [b, s.size]));
  return { count: writes.length, bytes, unknownBytes, byForm, byOffset, distinct };
}

/**
 * The functions of a listing, each delimited as asm-oracle delimits one: a
 * label at column 0 named by a `.type <name>, @function` directive, up to its
 * `.size <name>,`. A function whose closing `.size` is missing is left out
 * (a wrong boundary would import a neighbour's writes). Returns
 * [{fn, first, lines}] with `first` the listing line number of the label.
 */
export function listingFunctions(asm) {
  const lines = asm.split('\n');
  const names = new Set();
  for (const l of lines) {
    const m = /^\s*\.type\s+([^,\s]+)\s*,\s*[@%]function\b/.exec(l);
    if (m) names.add(m[1].replace(/^"|"$/g, ''));
  }
  const out = [];
  for (const fn of names) {
    const b = functionLines(lines, fn);
    if (b) out.push({ fn, ...b });
  }
  return out.sort((a, b) => a.first - b.first);
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function functionLines(lines, fn) {
  const startRe = new RegExp(`^${escapeRe(fn)}:`);
  const endRe = new RegExp(`^\\s*\\.size\\s+${escapeRe(fn)}\\s*,`);
  const start = lines.findIndex((l) => startRe.test(l));
  if (start === -1) return null;
  for (let j = start + 1; j < lines.length; j++) {
    if (endRe.test(lines[j])) return { first: start + 1, lines: lines.slice(start, j + 1) };
  }
  return null;
}

/**
 * One function's reading: {fn, writes, ...summarizeWrites}, or null when the
 * body cannot be delimited (no `fn:` label with a closing `.size fn,`).
 */
export function zeroWritesOf(asm, fn, opts = {}) {
  if (typeof asm !== 'string') return null;
  const all = asm.split('\n');
  const b = functionLines(all, fn);
  if (!b) return null;
  const externalRefs = opts.scope === 'function' ? labelsReferenced(all) : null;
  const writes = zeroWritesInLines(b.lines, { ...opts, first: b.first, externalRefs });
  return { fn, first: b.first, bodyLineCount: b.lines.length, writes, ...summarizeWrites(writes) };
}

/** Every function of a listing (listingFunctions), read. */
export function readListing(asm, opts = {}) {
  if (typeof asm !== 'string') throw new Error('readListing needs the listing text');
  const externalRefs = opts.scope === 'function' ? labelsReferenced(asm.split('\n')) : null;
  return listingFunctions(asm).map(({ fn, first, lines }) => {
    const writes = zeroWritesInLines(lines, { ...opts, first, externalRefs });
    return { fn, first, bodyLineCount: lines.length, writes, ...summarizeWrites(writes) };
  });
}
