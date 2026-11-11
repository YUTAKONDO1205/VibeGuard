/**
 * A reading of what is left of the repair in the optimised IR: per function,
 * the barriers WipePin and WipePinGcc place, the volatile memsets WipePin
 * makes, and volatile zero stores, counted in the text of clang's
 * `-S -emit-llvm` output and of gcc's `-fdump-tree-optimized` dump. Pure
 * functions: nothing here compiles or reads a file. The tests
 * (../../test/ir-pin-reading.test.mjs) reach all of it with no compiler.
 *
 * The forms, as the plugins build them and as the printers print them
 * (measured 2026-11-11 with clang-18 18.1.3 and gcc-13 13.3.0, -O0 and -O2):
 *
 *   WipePin's barrier (llvm-repair/src/WipePin.cpp, insertBarrierAfter and
 *   insertBufferBarrierBefore: InlineAsm::get(FT, "", "r,~{memory}", true))
 *       call void asm sideeffect "", "r,~{memory}"(ptr nonnull %1) #4
 *   WipePin's pin (the memset made volatile)
 *       call void @llvm.memset.p0.i64(ptr nonnull align 16 %1, i8 0, i64 32, i1 true)
 *   WipePinGcc's barrier (gcc-repair/src/WipePinGcc.cpp, buildPin and
 *   buildPinFor: one input with constraint "g", one clobber "memory", no
 *   outputs, volatile)
 *       __asm__ __volatile__("" :  : "g" &k : "memory");
 *
 * Telling a plugin's barrier from one the source wrote:
 *
 *   - clang: an `asm volatile("" : : "r"(p) : "memory")` written in C prints
 *     with the clobbers clang adds to every x86 inline asm,
 *     "r,~{memory},~{dirflag},~{fpsr},~{flags}", and carries `!srcloc`; the
 *     plugin's prints "r,~{memory}" exactly. This reading counts the exact form
 *     as `wipePinBarriers` and every other side-effecting asm with a memory
 *     clobber as `otherMemoryAsm`. IR not produced from C by clang (written by
 *     hand, or by another front end) can carry the exact form too.
 *   - gcc: the same source line written with "g" prints exactly as the
 *     plugin's barrier does, and nothing in the dump tells them apart. The
 *     exact form is `wipePinGccBarriers`, whoever wrote it; "r", "m" or more
 *     operands are `otherMemoryAsm`.
 *
 * Counted per function as well: zero-value memset intrinsics split by the
 * volatile flag (and the non-zero volatile ones), calls to the library zero
 * functions by name, and volatile stores of zero (`store volatile i64 0`,
 * `zeroinitializer`, `null`; gcc's `={v} 0;`, `={v} {};`, never
 * `={v} {CLOBBER}`), with their bytes when the stored type has a size this
 * file knows. GIMPLE has no volatile memset call: WipePinGcc's pin is the
 * barrier itself (WipePinGcc.cpp, header), and memset calls are counted as
 * `memsetZeroCalls` beside it.
 *
 * What a count is not: a barrier left in the IR is not a wipe that reached
 * the object (code generation runs after), a count after inlining can exceed
 * the number of barriers placed (a barrier is copied into every caller) or
 * fall below it (unreachable code is deleted), and a volatile store of zero is
 * a zero write, not necessarily a wipe.
 */

/** Split an argument list on the commas outside (), [], {} and <>. */
export function splitArgs(s) {
  const out = [];
  let depth = 0, cur = '', inStr = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"' && s[i - 1] !== '\\') inStr = !inStr;
    if (!inStr) {
      if ('([{<'.includes(ch)) depth++;
      else if (')]}>'.includes(ch)) depth--;
      if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    }
    cur += ch;
  }
  if (cur.trim() !== '') out.push(cur.trim());
  return out;
}

/** The text between the parenthesis at `open` and its match, or null. */
function balanced(s, open) {
  let depth = 0, inStr = false;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"' && s[i - 1] !== '\\') inStr = !inStr;
    if (inStr) continue;
    if (ch === '(') depth++;
    else if (ch === ')') { depth--; if (depth === 0) return s.slice(open + 1, i); }
  }
  return null;
}

/** The value of an IR argument: its last token (`i8 noundef 0` -> `0`). */
const lastToken = (arg) => arg.trim().split(/\s+/).pop();

const ZERO_IR = new Set(['0', 'zeroinitializer', 'null', 'false', '0.0', '0.000000e+00', '-0.0']);

/** The size in bytes of an IR type this file knows (iN, ptr, float, double, <N x T>, [N x T]); null otherwise. */
export function irTypeBytes(ty) {
  const t = ty.trim();
  let m = /^i(\d+)$/.exec(t);
  if (m) return Number(m[1]) % 8 === 0 ? Number(m[1]) / 8 : null;
  if (t === 'ptr' || /\*$/.test(t)) return 8;
  if (t === 'float') return 4;
  if (t === 'double') return 8;
  if (t === 'half' || t === 'bfloat') return 2;
  m = /^<\s*(\d+)\s+x\s+(.+)>$/.exec(t) ?? /^\[\s*(\d+)\s+x\s+(.+)\]$/.exec(t);
  if (m) { const e = irTypeBytes(m[2]); return e === null ? null : Number(m[1]) * e; }
  return null;
}

/** Library functions whose call writes zeros, counted by name when called. */
export const ZERO_CALLEES = ['memset', '__memset_chk', 'memset.inline', 'bzero', 'explicit_bzero',
  '__explicit_bzero_chk', 'memset_s', 'memset_explicit', 'sodium_memzero', 'SecureZeroMemory', 'OPENSSL_cleanse'];

const emptyCounts = () => ({
  wipePinBarriers: 0, otherMemoryAsm: 0,
  volatileMemsetZero: 0, volatileMemsetNonZero: 0, memsetZero: 0,
  volatileZeroStores: 0, volatileZeroStoreBytes: 0, volatileZeroStoresUnsized: 0,
  zeroCalls: {},
  lines: [],
});

// --------------------------------------------------------------- LLVM IR --

/**
 * The functions of an IR text: [{fn, first, lines}] from each `define` line to
 * the `}` at column 0 that closes it. A `define` with no closing brace is left
 * out.
 */
export function irFunctions(text) {
  const lines = text.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^define\b/.test(lines[i])) continue;
    const m = /@("(?:[^"\\]|\\.)*"|[-a-zA-Z$._][-a-zA-Z$._0-9]*|\d+)\s*\(/.exec(lines[i]);
    if (!m) continue;
    const fn = m[1].replace(/^"|"$/g, '');
    let j = i + 1;
    while (j < lines.length && lines[j] !== '}') j++;
    if (j >= lines.length) continue;
    out.push({ fn, first: i + 1, lines: lines.slice(i, j + 1) });
    i = j;
  }
  return out;
}

/** WipePin's barrier, exactly: an empty side-effecting asm with constraint "r,~{memory}" and one operand. */
export function isWipePinBarrier(line) {
  const m = /\bcall void asm sideeffect "", "r,~\{memory\}"\(/.exec(line);
  if (!m) return false;
  if (/asm sideeffect (alignstack|inteldialect)/.test(line)) return false;
  const args = balanced(line, m.index + m[0].length - 1);
  return args !== null && splitArgs(args).length === 1;
}

/** One IR function body read: the counts and the lines that made them. */
export function readIrBody(lines, first = 1) {
  const c = emptyCounts();
  lines.forEach((l, i) => {
    const n = first + i;
    if (/\basm\s+sideeffect\b/.test(l)) {
      if (isWipePinBarrier(l)) { c.wipePinBarriers++; c.lines.push({ line: n, kind: 'wipePinBarrier' }); }
      else if (/~\{memory\}/.test(l)) { c.otherMemoryAsm++; c.lines.push({ line: n, kind: 'otherMemoryAsm' }); }
      return;
    }
    let m = /\bcall void @llvm\.memset(?:\.inline)?\.p0[\w.]*\(/.exec(l);
    if (m) {
      const args = splitArgs(balanced(l, m.index + m[0].length - 1) ?? '');
      if (args.length >= 4) {
        const val = lastToken(args[1]);
        const vol = lastToken(args[3]) === 'true';
        const zero = val === '0';
        if (vol && zero) { c.volatileMemsetZero++; c.lines.push({ line: n, kind: 'volatileMemsetZero', length: Number.isFinite(Number(lastToken(args[2]))) ? Number(lastToken(args[2])) : null }); }
        else if (vol) { c.volatileMemsetNonZero++; c.lines.push({ line: n, kind: 'volatileMemsetNonZero' }); }
        else if (zero) c.memsetZero++;
      }
      return;
    }
    m = /\b(?:call|invoke)\b[^@]*@("(?:[^"\\]|\\.)*"|[-a-zA-Z$._][-a-zA-Z$._0-9]*)\s*\(/.exec(l);
    if (m) {
      const callee = m[1].replace(/^"|"$/g, '');
      if (ZERO_CALLEES.includes(callee)) c.zeroCalls[callee] = (c.zeroCalls[callee] ?? 0) + 1;
      return;
    }
    m = /\bstore\s+(?:atomic\s+)?volatile\s+(.+?)\s+(\S+),\s*(?:ptr|[^,]*\*)\s/.exec(l);
    if (m && ZERO_IR.has(m[2])) {
      c.volatileZeroStores++;
      const b = irTypeBytes(m[1]);
      if (b === null) c.volatileZeroStoresUnsized++; else c.volatileZeroStoreBytes += b;
      c.lines.push({ line: n, kind: 'volatileZeroStore', bytes: b });
    }
  });
  return c;
}

/** Every function of an IR text, read: [{fn, first, ...counts}]. */
export function readIr(text) {
  if (typeof text !== 'string') throw new Error('readIr needs the IR text');
  return irFunctions(text).map(({ fn, first, lines }) => ({ fn, first, ...readIrBody(lines, first) }));
}

// ---------------------------------------------------------------- GIMPLE --

/**
 * The functions of a `-fdump-tree-<pass>` dump: [{fn, display, first, lines}],
 * each from its `;; Function <display> (<name>, funcdef_no=...` header to the
 * next header. `fn` is the assembler name in the parentheses.
 */
export function gimpleFunctions(text) {
  const lines = text.split('\n');
  const heads = [];
  lines.forEach((l, i) => {
    const m = /^;; Function (.*?) \(([^,()\s]+), funcdef_no=/.exec(l);
    if (m) heads.push({ i, display: m[1], fn: m[2] });
  });
  return heads.map((h, k) => ({ fn: h.fn, display: h.display, first: h.i + 1,
    lines: lines.slice(h.i, k + 1 < heads.length ? heads[k + 1].i : lines.length) }));
}

/**
 * A GIMPLE asm statement: {volatile, template, outputs, inputs: [{constraint,
 * operand}], clobbers}, or null when the line is not one.
 */
export function parseGimpleAsm(line) {
  const m = /^\s*__asm__\s*(__volatile__)?\s*\(("(?:[^"\\]|\\.)*")(.*)\);\s*$/.exec(line);
  if (!m) return null;
  const parts = m[3].split(/\s*:\s*/);
  // parts[0] is '' (the text before the first colon); then outputs, inputs, clobbers[, labels]
  if (parts[0] !== '') return null;
  const ops = (s) => (s ? splitArgs(s) : []);
  const inputs = ops(parts[2]).map((x) => {
    const q = /^("(?:[^"\\]|\\.)*")\s*(.*)$/.exec(x);
    return q ? { constraint: JSON.parse(q[1]), operand: q[2] } : { constraint: null, operand: x };
  });
  const clobbers = ops(parts[3]).map((x) => x.replace(/^"|"$/g, ''));
  return { volatile: !!m[1], template: JSON.parse(m[2]), outputs: ops(parts[1]), inputs, clobbers, labels: ops(parts[4]) };
}

/** WipePinGcc's barrier, exactly: volatile, empty, no outputs, one "g" input, one "memory" clobber. */
export function isWipePinGccBarrier(line) {
  const a = parseGimpleAsm(line);
  return !!a && a.volatile && a.template === '' && a.outputs.length === 0 && a.inputs.length === 1
    && a.inputs[0].constraint === 'g' && a.clobbers.length === 1 && a.clobbers[0] === 'memory' && a.labels.length === 0;
}

/** One GIMPLE function read. */
export function readGimpleBody(lines, first = 1) {
  const c = emptyCounts();
  c.memsetZeroCalls = 0;
  lines.forEach((l, i) => {
    const n = first + i;
    const a = parseGimpleAsm(l);
    if (a) {
      if (isWipePinGccBarrier(l)) { c.wipePinBarriers++; c.lines.push({ line: n, kind: 'wipePinGccBarrier' }); }
      else if (a.clobbers.includes('memory')) { c.otherMemoryAsm++; c.lines.push({ line: n, kind: 'otherMemoryAsm' }); }
      return;
    }
    let m = /(?:^|=\s*|\s)(__builtin_memset|memset|__builtin___memset_chk|__memset_chk)\s*\((.*)\);\s*$/.exec(l);
    if (m) {
      const args = splitArgs(m[2]);
      if (args.length >= 3 && args[1] === '0') { c.memsetZeroCalls++; c.lines.push({ line: n, kind: 'memsetZeroCall' }); }
      const name = m[1].replace(/^__builtin_/, '').replace(/^_memset_chk$/, '__memset_chk');
      if (args.length >= 3 && args[1] === '0') c.zeroCalls[name] = (c.zeroCalls[name] ?? 0) + 1;
      return;
    }
    m = /(?:^|=\s*|\s)(bzero|explicit_bzero|__explicit_bzero_chk|memset_s|memset_explicit|sodium_memzero|OPENSSL_cleanse|__builtin_bzero)\s*\(/.exec(l);
    if (m) { const name = m[1].replace(/^__builtin_/, ''); c.zeroCalls[name] = (c.zeroCalls[name] ?? 0) + 1; return; }
    m = /^\s*(.+?)\s+=\{v\}\s+(.+?);\s*$/.exec(l);
    if (m && !/^\{CLOBBER/.test(m[2]) && /^(0|0B|0\.0|\{\})$/.test(m[2])) {
      c.volatileZeroStores++;
      c.volatileZeroStoresUnsized++;
      c.lines.push({ line: n, kind: 'volatileZeroStore', bytes: null });
    }
  });
  c.wipePinGccBarriers = c.wipePinBarriers;
  delete c.wipePinBarriers;
  delete c.volatileMemsetZero; delete c.volatileMemsetNonZero; delete c.memsetZero;
  delete c.volatileZeroStoreBytes;
  return c;
}

/** Every function of a GIMPLE dump, read: [{fn, display, first, ...counts}]. */
export function readGimple(text) {
  if (typeof text !== 'string') throw new Error('readGimple needs the dump text');
  return gimpleFunctions(text).map(({ fn, display, first, lines }) => ({ fn, display, first, ...readGimpleBody(lines, first) }));
}

/** Totals over a list of read functions (readIr or readGimple). */
export function totals(fns) {
  const t = {};
  for (const f of fns) {
    for (const [k, v] of Object.entries(f)) {
      if (typeof v === 'number' && k !== 'first') t[k] = (t[k] ?? 0) + v;
      if (k === 'zeroCalls') { t.zeroCalls ??= {}; for (const [n, x] of Object.entries(v)) t.zeroCalls[n] = (t.zeroCalls[n] ?? 0) + x; }
    }
  }
  t.functions = fns.length;
  return t;
}
