// Evasion-corpus PoC — is the vulnerability still THERE after the rewrite?
//
// WHY THIS EXISTS, AND WHY IT IS NOT THE SAME SCRIPT AS THE DISGUISE PoC.
//
// The disguise corpus never edits the payload's bytes, so "the vulnerability
// survived" is true by construction and the only open question is whether the
// file still parses. sec-b3-poc.mjs answers exactly that and says so.
//
// The evasion transforms in sec-b1-transforms.mjs DO edit the payload: a
// constant is cut in half and re-joined, a name is respelled as an escape, a
// method call becomes a dynamic member lookup, a receiver is rebound to a fresh
// local. Each of those is *argued* to preserve meaning in a comment next to the
// transform. An argument is not evidence. The generator's syntax gate
// (`python -m py_compile`, `node --check`) only establishes that the rewrite is
// still a valid program — a file can parse perfectly and no longer do the thing
// that made it vulnerable.
//
// So this script asks the harder question, and splits the corpus in two to ask
// it in the cheapest sound way for each half:
//
//   mode 'execute'      The finding names a runtime SINK — a shell, an
//                       interpreter, a deserializer, a query, a DOM write. What
//                       the sink is *handed* is what makes the code vulnerable,
//                       and every one of the byte-editing transforms could
//                       plausibly change it. Nothing short of running the code
//                       settles it, so the code is run: the payload's own
//                       statement region is executed in a sandbox where EVERY
//                       free name resolves to a recording stand-in, and the call
//                       trace of the rewritten region is compared against the
//                       trace of the original line. A real shell is never
//                       spawned, a real deserializer never runs; the sink is the
//                       marker.
//
//   mode 'constructive' The finding is a property of a VALUE, not of an event: a
//                       credential literal, a weak algorithm name, a flag set to
//                       an unsafe constant, a placeholder marker left in source.
//                       There is no sink to fire — the rule fires on the value
//                       being present at all. The transforms in scope re-spell
//                       that value (split it, hex-escape it, move it into a
//                       temporary, turn a member name into a string) and every
//                       one of those reductions is decidable on the text: fold
//                       the concatenations, decode the escapes, and check the
//                       original's constants and names are all still there. That
//                       check is performed here — it is a measurement, not a
//                       claim — and combined with the syntax gate it is sufficient. Executing
//                       these would observe nothing that the syntax gate and the fold do not
//                       already establish.
//
// The split itself is a deliverable, not an implementation detail: FAMILY_MODE
// below is emitted verbatim into the output as `familyEvidence`, so a reader can
// see which vulnerabilities were shown to survive by observation and which by
// construction, and disagree with the line if they want to.
//
// HONESTY RULES BAKED IN
//   * A sink that does not fire is counted as "semantic preservation NOT
//     demonstrated", never quietly dropped or folded into a pass.
//   * A language with no toolchain on this machine is 'unverified', never a pass.
//   * A negative control is expected to differ, and is scored against that
//     expectation instead of being excluded.
//
// Run from the repo root AFTER the generator:
//   node scripts/sec-b1-gen-corpus.mjs && node scripts/sec-b1-poc.mjs
//
// Writes security-experiment/_results/b1-poc.json. Deterministic: inputs sorted,
// no RNG, and the only clock-dependent field is provenance.generatedAt.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { LANG_PROFILES, scanLineLiterals } from './sec-b1-transforms.mjs';

const MANIFEST = 'security-experiment/_results/b1-corpus-manifest.json';
const OUT = 'security-experiment/_results/b1-poc.json';
const PROBE_DIR = join(tmpdir(), 'vg-b1-poc');

if (!existsSync(MANIFEST)) {
  console.error(`corpus manifest not found at ${MANIFEST}\nFix: node scripts/sec-b1-gen-corpus.mjs`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// The evidence split. `mode` decides which check a pair gets; `justification` is
// the one-line reason, and is copied into the output rather than paraphrased.
// ---------------------------------------------------------------------------
const FAMILY_MODE = {
  'code-execution': {
    mode: 'execute',
    justification:
      'The finding is an interpreter being handed a string. Splitting or re-spelling that string is exactly the edit that could change what gets interpreted, so the interpreter call is observed with a recording stand-in instead of a real one.',
  },
  'command-injection': {
    mode: 'execute',
    justification:
      'The finding is a shell receiving an assembled command. The assembled value is the vulnerability, and a concatenation split or hex escape rewrites precisely that value, so it is observed at the call rather than assumed.',
  },
  'unsafe-deserialization': {
    mode: 'execute',
    justification:
      'The finding is a deserializer reached with attacker-controlled input; a dynamic-member or alias rewrite can silently retarget the call to a different function, which only the observed callee path can rule out.',
  },
  'query-injection': {
    mode: 'execute',
    justification:
      'The finding is a query string built by concatenation, and the concatenation-splitting transforms edit that construction directly, so the string actually handed to the query call is captured and compared.',
  },
  'markup-injection': {
    mode: 'execute',
    justification:
      'The finding is a markup sink assigned a non-literal value; hoisting or aliasing the assigned expression could change what reaches the sink, so the assignment is observed.',
  },
  'dynamic-attribute-access': {
    mode: 'execute',
    justification:
      'The finding is a member resolved at runtime from a string, so the resolved callee cannot be read off the source at all and must be observed.',
  },
  'dynamic-import': {
    mode: 'execute',
    justification:
      'The finding is a module path resolved at runtime, so which module is loaded is only knowable by running the resolution.',
  },
  'hardcoded-secret': {
    mode: 'constructive',
    justification:
      'The finding is the credential literal being present; the transforms only re-spell that literal, and folding the concatenations plus decoding the escapes recovers the identical value, so there is no runtime event execution could add.',
  },
  'weak-crypto-constant': {
    mode: 'constructive',
    justification:
      'The finding is determined by a constant algorithm or scheme name, which every transform in scope reduces back to the same string, so constructive equality of that constant plus the syntax gate settles survival.',
  },
  'insecure-config': {
    mode: 'constructive',
    justification:
      'The finding is a configuration key bound to an unsafe constant; the transforms move or re-spell the binding but cannot change the bound value, and the fold check verifies the key and value are both still present.',
  },
  'source-marker': {
    mode: 'constructive',
    justification:
      'The finding is a textual marker (placeholder, stub body, misleading name) with no runtime sink at all — there is nothing for an execution probe to observe, so preserving the marker constructively is the whole of the claim.',
  },
};

/** Rule identifier -> family. A rule absent from this table is a hard error
 *  rather than a silent default: an unclassified rule would be scored by
 *  whichever mode happened to be the fallback, which is the exact kind of
 *  quiet assumption this script exists to remove. */
const FAMILY_BY_RULE = {
  'VG-INJ-004': 'code-execution',
  'VG-INJ-014': 'code-execution',
  'VG-INJ-002': 'command-injection',
  'VG-INJ-003': 'command-injection',
  'VG-INJ-010': 'command-injection',
  'VG-INJ-005': 'unsafe-deserialization',
  'VG-INJ-012': 'unsafe-deserialization',
  'VG-INJ-018': 'unsafe-deserialization',
  'VG-INJ-001': 'query-injection',
  'VG-INJ-008': 'query-injection',
  'VG-INJ-019': 'query-injection',
  'VG-INJ-006': 'markup-injection',
  'VG-INJ-009': 'markup-injection',
  'VG-INJ-013': 'markup-injection',
  'VG-INJ-016': 'dynamic-attribute-access',
  'VG-INJ-017': 'dynamic-import',
  'VG-SEC-001': 'hardcoded-secret',
  'VG-SEC-002': 'hardcoded-secret',
  'VG-SEC-003': 'hardcoded-secret',
  'VG-SEC-004': 'hardcoded-secret',
  'VG-AUTH-003': 'hardcoded-secret',
  'VG-CRYPTO-001': 'weak-crypto-constant',
  'VG-CRYPTO-002': 'weak-crypto-constant',
  'VG-CRYPTO-003': 'weak-crypto-constant',
  'VG-AUTH-001': 'insecure-config',
  'VG-AUTH-004': 'insecure-config',
  'VG-AUTH-005': 'insecure-config',
  'VG-AUTH-006': 'insecure-config',
  'VG-AUTH-007': 'insecure-config',
  'VG-FW-001': 'insecure-config',
  'VG-FW-002': 'insecure-config',
  'VG-FW-003': 'insecure-config',
  'VG-FW-004': 'insecure-config',
  'VG-QUAL-002': 'insecure-config',
  'VG-QUAL-004': 'insecure-config',
  'VG-QUAL-008': 'insecure-config',
  'VG-AUTH-002': 'source-marker',
  'VG-QUAL-001': 'source-marker',
  'VG-QUAL-003': 'source-marker',
  'VG-QUAL-005': 'source-marker',
  'VG-QUAL-006': 'source-marker',
  'VG-QUAL-007': 'source-marker',
  'VG-QUAL-009': 'source-marker',
  'VG-QUAL-010': 'source-marker',
  'VG-INJ-007': 'source-marker',
  'VG-INJ-011': 'insecure-config',
  'VG-INJ-015': 'insecure-config',
};

/** The transforms' own temporary-name prefix, mirrored from
 *  sec-b1-transforms.mjs. Names it introduced are the harness's own footprint,
 *  not the program's, so they are normalized out of both comparisons. */
const VG_PREFIX = '_vgB1';

/** Negative controls, scored against their declared expectation instead of
 *  being dropped. NC1 really removes the vulnerability, so a difference is the
 *  correct outcome and an EQUIVALENCE would mean the check is blind. */
const CONTROL_EXPECT = { NC1: 'differs', NC2: 'identical' };

// ---------------------------------------------------------------------------
// Statement-region extraction
// ---------------------------------------------------------------------------

/**
 * The lines of the transformed file that together carry the payload: the
 * payload line plus the maximal run of CONTIGUOUS changed lines touching it.
 *
 * The run matters because several transforms move part of the payload out of
 * its line — an argument hoisted into a temporary above, a continuation pushed
 * below, a tautology wrapper straddling it. Executing the payload line alone
 * would leave the hoisted temporary unbound and score a working transform as
 * broken. A changed line far from the payload (the aliased import that N1
 * rewrites near the top of the file) is deliberately NOT pulled in: it is not
 * part of the statement, and the alias it introduces is handled by name
 * normalization instead.
 */
function payloadRegion(totalLines, payloadLine, changedLines) {
  const changed = new Set(changedLines ?? []);
  let lo = payloadLine;
  let hi = payloadLine;
  while (lo - 1 >= 1 && changed.has(lo - 1)) lo -= 1;
  while (hi + 1 <= totalLines && changed.has(hi + 1)) hi += 1;
  return { lo, hi };
}

/** Strip the shallowest common indentation so the region is legal at column 0.
 *  Python needs this; every other language is indifferent to it. */
function dedent(lines) {
  const pads = lines.filter((l) => l.trim() !== '').map((l) => (l.match(/^[ \t]*/) || [''])[0].length);
  const cut = pads.length ? Math.min(...pads) : 0;
  return lines.map((l) => l.slice(Math.min(cut, (l.match(/^[ \t]*/) || [''])[0].length)));
}

const readLines = (p) => readFileSync(p, 'utf8').replace(/\r\n/g, '\n').split('\n');

// ---------------------------------------------------------------------------
// Constructive equivalence
//
// The question: after folding every concatenation the language really performs
// and decoding every escape the lexer really decodes, is each constant value and
// each name mentioned by the original payload line still mentioned by the
// rewritten region?
//
// It is deliberately a SUBSET test and not an equality test. Every transform is
// allowed to add material (a temporary, a wrapper, a `getattr`); none is allowed
// to lose the constant or the callee that made the line a finding. Equality
// would reject correct transforms; a subset test rejects exactly the failure
// mode that matters.
//
// A member name turned into a string is intentionally NOT a loss: `md5` and
// `"md5"` enter the bag as the same element, because a dynamic lookup by that
// string resolves to that member. That is the one equivalence this check grants
// beyond folding, and it is why the dynamic-access rule families are executed
// rather than trusted to this path.
// ---------------------------------------------------------------------------

const LIT_MARK = '';

/** Decode the escapes the lexers actually decode. Anything unrecognised keeps
 *  its backslash, so an unknown escape can never silently become a different
 *  character. */
function decodeEscapes(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '\\') { out += s[i]; continue; }
    const n = s[i + 1];
    if (n === 'x' && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 2, i + 4))) {
      out += String.fromCharCode(parseInt(s.slice(i + 2, i + 4), 16));
      i += 3;
    } else if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 2, i + 6))) {
      out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16));
      i += 5;
    } else if (n === 'n') { out += '\n'; i += 1; }
    else if (n === 't') { out += '\t'; i += 1; }
    else if (n === 'r') { out += '\r'; i += 1; }
    else if (n === '\\' || n === "'" || n === '"') { out += n; i += 1; }
    else out += s[i];
  }
  return out;
}

/** Languages whose `/` opens a regex literal by DELIMITER rather than by a
 *  call. Kept here rather than read off LANG_PROFILES because that table is a
 *  mirror of the analyzer's and does not carry this flag. */
const REGEX_LITERAL_LANGS = new Set(['javascript', 'typescript']);

/**
 * The end of a JavaScript regex literal starting at `i`, or -1 if the line does
 * not close one. A `/` inside a character class does not terminate the literal,
 * which is the whole reason this function has to exist: `/[/*]/` is one token,
 * and a scanner that models only strings and comments reads its second character
 * as a block-comment opener and then swallows everything after it — including
 * the payload. This checker hit exactly that, so it models the construct the
 * same way the canonicalizer does, and for the same reason.
 */
function regexLiteralEnd(line, i) {
  let k = i + 1;
  let inClass = false;
  while (k < line.length) {
    const c = line[k];
    if (c === '\\') { k += 2; continue; }
    if (inClass) { if (c === ']') inClass = false; }
    else if (c === '[') inClass = true;
    else if (c === '/') {
      k += 1;
      while (k < line.length && /[a-z]/.test(line[k])) k += 1; // flags
      return k;
    }
    k += 1;
  }
  return -1; // unterminated: fall back to reading the `/` as division (safe direction)
}

/** Whether the previous significant character can END a value, which is what
 *  decides division vs. regex at a `/`. Ambiguity resolves to division. */
const endsValue = (c) => c != null && /[A-Za-z0-9_$)\]]/.test(c);

/**
 * Replace every string literal in `lines` with a marker and every comment with
 * spaces, returning the masked text plus the decoded literal values. Block
 * comment state is carried across lines, which is why this works on a region
 * rather than a line.
 */
function maskRegion(lines, profile, language) {
  const values = [];
  const masked = [];
  let inBlock = false;
  for (const raw of lines) {
    let line = raw;
    let prefix = '';
    if (inBlock) {
      const close = line.indexOf('*/');
      if (close === -1) { masked.push(' '.repeat(line.length)); continue; }
      prefix = ' '.repeat(close + 2);
      line = line.slice(close + 2);
      inBlock = false;
    }
    const lits = scanLineLiterals(line, profile);
    let out = '';
    let i = 0;
    let last = null; // last significant code character, for the regex/division call
    while (i < line.length) {
      const lit = lits.find((l) => i >= l.start && i < l.end);
      if (lit) {
        values.push(lit.tripleQuoted ? null : decodeEscapes(lit.inner));
        out += `${LIT_MARK}${values.length - 1}${LIT_MARK}`;
        i = lit.end;
        last = ')'; // a literal ends a value
        continue;
      }
      if (profile.lineComment && line.startsWith(profile.lineComment, i)) { out += ' '.repeat(line.length - i); break; }
      if (profile.blockComment && line.startsWith('/*', i)) {
        const close = line.indexOf('*/', i + 2);
        if (close === -1) { inBlock = true; out += ' '.repeat(line.length - i); break; }
        out += ' '.repeat(close + 2 - i);
        i = close + 2;
        continue;
      }
      // AFTER the two comment forms, never before: a valid regex cannot begin
      // `//` or `/*`, so testing regex first would misread a real comment.
      if (REGEX_LITERAL_LANGS.has(language) && line[i] === '/' && !endsValue(last)) {
        const end = regexLiteralEnd(line, i);
        if (end !== -1) {
          out += ' '.repeat(end - i); // inert: names inside a regex body are data
          i = end;
          last = ')';
          continue;
        }
      }
      out += line[i];
      if (line[i] !== ' ' && line[i] !== '\t') last = line[i];
      i += 1;
    }
    masked.push(prefix + out);
  }
  return { text: masked.join('\n'), values };
}

/**
 * The bag of constants and names a region mentions.
 *
 * Folding runs to a fixed point over the masked text: two literal markers
 * separated by nothing but whitespace, newlines and (at most one) real
 * concatenation operator become a single literal whose value is the
 * concatenation. That is the same condition the canonicalizer's fold uses,
 * minus its single-line restriction — here the point is what the RUNTIME does,
 * and the runtime does not care which line the operand sits on.
 */
function symbolBag(lines, language) {
  const profile = LANG_PROFILES[language];
  if (!profile) return null;
  const { text, values } = maskRegion(lines, profile, language);
  const op = profile.concatOp;
  const opPat = op === '.' ? '\\.' : '\\+';
  const gap = profile.adjacencyConcat ? `(?:\\s|\\\\\\n)*(?:${opPat})?(?:\\s|\\\\\\n)*` : `(?:\\s|\\\\\\n)*${opPat}(?:\\s|\\\\\\n)*`;
  const foldRe = new RegExp(`${LIT_MARK}(\\d+)${LIT_MARK}${gap}${LIT_MARK}(\\d+)${LIT_MARK}`);
  let folded = text;
  for (let guard = 0; guard < 200; guard++) {
    const m = foldRe.exec(folded);
    if (!m) break;
    const a = values[Number(m[1])];
    const b = values[Number(m[2])];
    if (a == null || b == null) break;
    values.push(a + b);
    folded = folded.slice(0, m.index) + `${LIT_MARK}${values.length - 1}${LIT_MARK}` + folded.slice(m.index + m[0].length);
  }

  const bag = new Set();
  const surviving = new Set();
  for (const m of folded.matchAll(new RegExp(`${LIT_MARK}(\\d+)${LIT_MARK}`, 'g'))) surviving.add(Number(m[1]));
  for (const idx of surviving) {
    const v = values[idx];
    if (v != null && v !== '') bag.add(`lit:${v}`);
  }

  // Identifiers, with unicode escapes resolved first — `crypto` and
  // `crypto` are the same binding to the lexer and must be the same element
  // here.
  const code = decodeEscapes(folded.replace(new RegExp(`${LIT_MARK}\\d+${LIT_MARK}`, 'g'), ' ')).replace(/ /g, ' ');
  for (const m of code.matchAll(/[A-Za-z_$][\w$]*/g)) bag.add(`id:${m[0]}`);
  return bag;
}

/** Drop the harness's own temporaries and undo its import aliasing, so the
 *  comparison is between the two PROGRAMS and not between the harness and
 *  itself. */
function normalizeBag(bag) {
  const out = new Set();
  for (const e of bag) {
    const [kind, ...rest] = [e.slice(0, e.indexOf(':')), e.slice(e.indexOf(':') + 1)];
    let v = rest.join('');
    if (kind === 'id') {
      if (v === VG_PREFIX || v.startsWith(`${VG_PREFIX}Re`) || v.startsWith(`${VG_PREFIX}Recv`) ||
          v.startsWith(`${VG_PREFIX}Arg`) || v.startsWith(`${VG_PREFIX}Fn`)) continue;
      if (v.startsWith(`${VG_PREFIX}_`)) v = v.slice(VG_PREFIX.length + 1);
    }
    out.add(`${kind}:${v}`);
  }
  return out;
}

/** `md5` and `"md5"` are the same element for the subset test — a dynamic
 *  lookup by that string resolves to that member. */
const bagHas = (bag, e) => bag.has(e) || (e.startsWith('id:') && bag.has(`lit:${e.slice(3)}`)) ||
  (e.startsWith('lit:') && bag.has(`id:${e.slice(4)}`));

// ---------------------------------------------------------------------------
// Execution observation
//
// Both probes build the same thing: a scope in which EVERY free name resolves to
// a recorder. A recorder answers any member access with another recorder, and
// any call by appending one line to a trace and returning a further recorder.
// Nothing the payload names is real, so `os.system`, `pickle.loads`, `eval` and
// `cursor.execute` are all inert while still being observable — that is the
// "sink replaced by a harmless marker" the b3 script's discipline asks for.
//
// The comparison is trace-vs-trace, original region against rewritten region.
// Equal traces mean the same callee received the same argument VALUES, which is
// the property the transforms claim and a syntax check cannot see.
// ---------------------------------------------------------------------------

const JS_PROBE = String.raw`
import { readFileSync } from 'node:fs';
const render = (v) => {
  if (typeof v === 'function' && typeof v.__vgPath === 'string') return '<' + v.__vgPath + '>';
  if (typeof v === 'string') return JSON.stringify(v);
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') return String(v);
  if (Array.isArray(v)) return '[' + v.map(render).join(', ') + ']';
  return '<' + typeof v + '>';
};
function rec(trace, path) {
  const target = function () {};
  return new Proxy(target, {
    get(t, k) {
      if (k === '__vgPath') return path;
      if (k === Symbol.toPrimitive) return () => '<' + path + '>';
      if (k === 'toString') return () => '<' + path + '>';
      if (typeof k === 'symbol') return undefined;
      return rec(trace, path + '.' + String(k));
    },
    // An assignment IS a sink for the markup rules: an innerHTML write calls
    // nothing, so a probe that recorded only calls would see nothing happen and
    // report a working transform as unobservable.
    set(t, k, v) {
      if (typeof k !== 'symbol') trace.push('set ' + path + '.' + String(k) + ' = ' + render(v));
      return true;
    },
    has() { return true; },
    apply(t, self, args) {
      trace.push('call ' + path + '(' + args.map(render).join(', ') + ')');
      return rec(trace, path + '()');
    },
    construct(t, args) {
      trace.push('new ' + path + '(' + args.map(render).join(', ') + ')');
      return rec(trace, 'new ' + path);
    },
  });
}
const jobs = readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
for (const job of jobs) {
  const trace = [];
  const scope = new Proxy({}, {
    has: (t, k) => k !== Symbol.unscopables,
    get: (t, k) => (typeof k === 'symbol' ? undefined : rec(trace, String(k))),
    // Some payloads BUILD the dangerous value and hand it to a sink on a later
    // line the transform never touched. Recording what the region binds makes
    // that value comparable instead of invisible.
    set: (t, k, v) => {
      if (typeof k !== 'symbol') trace.push('bind ' + String(k) + ' = ' + render(v));
      return true;
    },
  });
  let error = null;
  try {
    // Sloppy-mode function body, so \`with\` is available: it is the only
    // construct that routes free identifiers through a proxy.
    // eslint-disable-next-line no-new-func
    new Function('__vgScope', 'with (__vgScope) {\n' + job.src + '\n}')(scope);
  } catch (e) {
    error = String((e && e.message) || e).split('\n')[0];
  }
  process.stdout.write(JSON.stringify({ id: job.id, trace, error }) + '\n');
}
`;

const PY_PROBE = String.raw`
import sys, json

def render(v):
    if isinstance(v, Rec):
        return '<' + object.__getattribute__(v, '_p') + '>'
    if isinstance(v, str):
        return json.dumps(v)
    if v is None or isinstance(v, (int, float, bool)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return '[' + ', '.join(render(x) for x in v) + ']'
    return '<' + type(v).__name__ + '>'

class Rec:
    def __init__(self, trace, path):
        object.__setattr__(self, '_t', trace)
        object.__setattr__(self, '_p', path)

    def __getattr__(self, k):
        if k.startswith('__') and k.endswith('__'):
            raise AttributeError(k)
        return Rec(object.__getattribute__(self, '_t'), object.__getattribute__(self, '_p') + '.' + k)

    def __setattr__(self, k, v):
        # An attribute write is a sink in its own right; recording it is what
        # lets an assignment-shaped payload be observed at all.
        object.__getattribute__(self, '_t').append(
            'set ' + object.__getattribute__(self, '_p') + '.' + k + ' = ' + render(v))

    def __call__(self, *a, **kw):
        t = object.__getattribute__(self, '_t')
        p = object.__getattribute__(self, '_p')
        parts = [render(x) for x in a] + [k + '=' + render(v) for k, v in kw.items()]
        t.append('call ' + p + '(' + ', '.join(parts) + ')')
        return Rec(t, p + '()')

    def __getitem__(self, k):
        return Rec(object.__getattribute__(self, '_t'), object.__getattribute__(self, '_p') + '[' + render(k) + ']')

    def __setitem__(self, k, v):
        object.__getattribute__(self, '_t').append(
            'set ' + object.__getattribute__(self, '_p') + '[' + render(k) + '] = ' + render(v))

    def __str__(self):
        return '<' + object.__getattribute__(self, '_p') + '>'

    __repr__ = __str__

    def __add__(self, o):
        return Rec(object.__getattribute__(self, '_t'), object.__getattribute__(self, '_p') + '+' + render(o))

    def __radd__(self, o):
        return Rec(object.__getattribute__(self, '_t'), render(o) + '+' + object.__getattribute__(self, '_p'))

    def __mod__(self, o):
        return Rec(object.__getattribute__(self, '_t'), object.__getattribute__(self, '_p') + '%' + render(o))

    def __iter__(self):
        return iter(())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __bool__(self):
        return True


class Scope(dict):
    def __init__(self, trace):
        super().__init__()
        self._t = trace

    def __missing__(self, k):
        return Rec(self._t, k)

# The ONLY real callables handed to the payload. Every one is pure and cannot
# touch the filesystem, the network or a subprocess. \`getattr\` is the load
# bearing entry: without it a dynamic-member rewrite would be recorded as a call
# to \`getattr\` instead of resolving to the member, and an equivalent transform
# would be scored as divergent. \`open\`, \`eval\`, \`exec\`, \`__import__\` are
# deliberately absent, so they resolve to recorders and stay inert.
SAFE = {}
for _n in ('getattr', 'str', 'int', 'float', 'bool', 'list', 'tuple', 'dict', 'set',
           'len', 'range', 'enumerate', 'zip', 'isinstance', 'type', 'bytes',
           'chr', 'ord', 'hex', 'abs', 'min', 'max', 'sum', 'sorted', 'repr',
           'Exception', 'ValueError', 'KeyError', 'TypeError'):
    SAFE[_n] = getattr(__builtins__, _n) if hasattr(__builtins__, _n) else __builtins__[_n]

with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    jobs = [json.loads(l) for l in fh if l.strip()]

def attempt(src, trace):
    g = Scope(trace)
    g['__builtins__'] = {}
    g.update(SAFE)
    try:
        exec(compile(src, '<payload>', 'exec'), g)
        # Same reason as the JS probe's set trap: a region that only BUILDS the
        # dangerous value has no call to observe, so its bindings are what must
        # be compared.
        for k in sorted(g):
            if k in SAFE or k == '__builtins__' or k.startswith('_vg'):
                continue
            trace.append('bind ' + k + ' = ' + render(g[k]))
        return None
    except BaseException as e:
        return type(e).__name__ + ': ' + str(e).split('\n')[0]


def indent(src):
    return '\n'.join('    ' + l for l in src.split('\n'))

out = sys.stdout
for job in jobs:
    trace = []
    err = attempt(job['src'], trace)
    wrapped = False
    # A payload lifted out of a function body can legitimately contain a return
    # or yield statement, which are SyntaxErrors at module level. That is an artifact of
    # excerpting, not a property of the rewrite, so the region is retried inside
    # a function. The retry starts from a FRESH trace so a partial first attempt
    # cannot be counted twice. Both arms of a pair go through the identical
    # procedure, so the comparison stays like-for-like.
    if err is not None and err.startswith('SyntaxError'):
        retry = []
        err2 = attempt('def _vg_region():\n' + indent(job['src']) + '\n_vg_region()', retry)
        if err2 is None:
            trace, err, wrapped = retry, None, True
    out.write(json.dumps({'id': job['id'], 'trace': trace, 'error': err, 'wrapped': wrapped}) + '\n')
    out.flush()
`;

const PROBES = {
  javascript: { file: 'probe.mjs', src: JS_PROBE, cmd: 'node', args: (probe, jobs) => [probe, jobs] },
  typescript: null, // no TypeScript pair reaches an execute-mode family in this corpus
  python: { file: 'probe.py', src: PY_PROBE, cmd: 'python', args: (probe, jobs) => [probe, jobs] },
};

/** Is the interpreter present? Probed once per language, and its ABSENCE is a
 *  recorded outcome rather than a crash. */
const available = {};
function probeAvailable(language) {
  if (language in available) return available[language];
  const p = PROBES[language];
  if (!p) return (available[language] = false);
  try {
    execFileSync(p.cmd, ['--version'], { stdio: 'pipe' });
    available[language] = true;
  } catch {
    available[language] = false;
  }
  return available[language];
}

/** Normalize the harness's own names out of a trace, for the same reason
 *  `normalizeBag` does it: an import the transform aliased is still the same
 *  module, and the alias is our footprint. */
const normalizeTrace = (trace) =>
  trace
    .filter((t) => !t.startsWith(`bind ${VG_PREFIX}`))
    .map((t) => t.replace(new RegExp(`\\b${VG_PREFIX}_`, 'g'), ''));

function runProbes(language, jobs) {
  const p = PROBES[language];
  mkdirSync(PROBE_DIR, { recursive: true });
  const probePath = join(PROBE_DIR, `${language}-${p.file}`);
  const jobsPath = join(PROBE_DIR, `${language}-jobs.ndjson`);
  writeFileSync(probePath, p.src);
  writeFileSync(jobsPath, jobs.map((j) => JSON.stringify(j)).join('\n') + '\n');
  const out = new Map();
  let stdout = '';
  try {
    stdout = execFileSync(p.cmd, p.args(probePath, jobsPath), {
      stdio: 'pipe',
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      timeout: 300000,
    });
  } catch (err) {
    // A crashed or timed-out batch still yields whatever it managed to write;
    // the jobs it never reached simply have no entry and are reported as
    // not-executed, which is the honest reading.
    stdout = String(err.stdout ?? '');
  }
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      out.set(r.id, r);
    } catch {
      /* a probe line we cannot parse is a missing observation, not a pass */
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
const pairs = [...manifest.pairs].sort((a, b) =>
  `${a.pairId}|${a.transformId}`.localeCompare(`${b.pairId}|${b.transformId}`),
);

const unknownRules = [...new Set(pairs.map((p) => p.ruleId))].filter((r) => !FAMILY_BY_RULE[r]).sort();
if (unknownRules.length) {
  console.error(`unclassified rule(s), refusing to score them by a default mode:\n  ${unknownRules.join('\n  ')}`);
  console.error('Fix: add each to FAMILY_BY_RULE in this file.');
  process.exit(1);
}

/** Everything needed to score one pair, computed before any interpreter runs. */
const prepared = [];
for (const p of pairs) {
  const family = FAMILY_BY_RULE[p.ruleId];
  const { mode } = FAMILY_MODE[family];
  const rec = {
    pairId: p.pairId,
    transformId: p.transformId,
    ruleId: p.ruleId,
    family,
    mode,
    language: p.language,
    control: CONTROL_EXPECT[p.transformId] ?? null,
    verdict: null,
    detail: null,
  };
  if (!existsSync(p.origPath) || !existsSync(p.transformedPath)) {
    rec.verdict = 'missing';
    rec.detail = 'original or transformed file listed in the manifest is not on disk';
    prepared.push(rec);
    continue;
  }
  const origLines = readLines(p.origPath);
  const transLines = readLines(p.transformedPath);
  const origLine = origLines[p.origPayloadLine - 1];
  if (origLine == null || transLines[p.expectedPayloadLine - 1] == null) {
    rec.verdict = 'missing';
    rec.detail = 'payload line index is outside the file';
    prepared.push(rec);
    continue;
  }
  const region = payloadRegion(transLines.length, p.expectedPayloadLine, p.changedLines);
  rec.regionLines = [region.lo, region.hi];
  rec.origSrc = dedent([origLine]).join('\n');
  rec.transSrc = dedent(transLines.slice(region.lo - 1, region.hi)).join('\n');
  prepared.push(rec);
}

// --- constructive pairs -----------------------------------------------------
for (const rec of prepared) {
  if (rec.mode !== 'constructive' || rec.verdict) continue;
  const origBag = symbolBag(rec.origSrc.split('\n'), rec.language);
  const transBag = symbolBag(rec.transSrc.split('\n'), rec.language);
  if (!origBag || !transBag) {
    rec.verdict = 'unverified';
    rec.detail = `no concatenation model for ${rec.language}`;
    continue;
  }
  const o = normalizeBag(origBag);
  const t = normalizeBag(transBag);
  const missing = [...o].filter((e) => !bagHas(t, e)).sort();
  const identical = missing.length === 0 && o.size === t.size && [...t].every((e) => bagHas(o, e));
  if (rec.control === 'differs') {
    rec.verdict = missing.length > 0 ? 'control-differs-as-expected' : 'control-unexpectedly-equivalent';
    rec.detail = missing.length > 0 ? `repair removed: ${missing.join(', ')}` : 'the repair control did not change any constant or name — the check may be blind here';
  } else if (rec.control === 'identical') {
    rec.verdict = identical ? 'control-identical-as-expected' : 'control-unexpectedly-differs';
    rec.detail = identical ? null : `identity transform changed the bag: missing ${missing.join(', ') || '(none)'}`;
  } else if (missing.length === 0) {
    rec.verdict = 'constructive-equivalent';
    rec.detail = null;
  } else {
    rec.verdict = 'constructive-lost';
    rec.detail = `constants/names present in the original payload and absent after the rewrite: ${missing.join(', ')}`;
  }
}

// --- execute pairs ----------------------------------------------------------
const byLanguage = new Map();
for (const rec of prepared) {
  if (rec.mode !== 'execute' || rec.verdict) continue;
  if (!probeAvailable(rec.language)) {
    rec.verdict = 'unverified';
    rec.detail = PROBES[rec.language]
      ? `no ${rec.language} interpreter on this machine`
      : `no execution probe implemented for ${rec.language}`;
    continue;
  }
  if (!byLanguage.has(rec.language)) byLanguage.set(rec.language, []);
  byLanguage.get(rec.language).push(rec);
}

for (const [language, recs] of [...byLanguage.entries()].sort()) {
  const jobs = [];
  for (let i = 0; i < recs.length; i++) {
    jobs.push({ id: `o${i}`, src: recs[i].origSrc });
    jobs.push({ id: `t${i}`, src: recs[i].transSrc });
  }
  const results = runProbes(language, jobs);
  for (let i = 0; i < recs.length; i++) {
    const rec = recs[i];
    const o = results.get(`o${i}`);
    const t = results.get(`t${i}`);
    if (!o || !t) {
      rec.verdict = 'not-executed';
      rec.detail = 'the probe produced no observation for this pair (batch ended early)';
      continue;
    }
    const ot = normalizeTrace(o.trace);
    const tt = normalizeTrace(t.trace);
    rec.origTrace = ot;
    rec.transformedTrace = tt;
    // A control whose region fires nothing gives the probe nothing to compare.
    // Calling that "as expected" either way would be a vacuous pass, so it is
    // named as an absent observation instead.
    if (rec.control && ot.length === 0 && tt.length === 0) {
      rec.verdict = 'control-not-observed';
      rec.detail = 'neither region called anything, so this control neither confirms nor refutes the probe';
      continue;
    }
    if (rec.control === 'differs') {
      const differs = JSON.stringify(ot) !== JSON.stringify(tt);
      rec.verdict = differs ? 'control-differs-as-expected' : 'control-unexpectedly-equivalent';
      rec.detail = differs ? null : 'the repair control produced an identical trace — the probe may be blind here';
      continue;
    }
    if (rec.control === 'identical') {
      const same = JSON.stringify(ot) === JSON.stringify(tt);
      rec.verdict = same ? 'control-identical-as-expected' : 'control-unexpectedly-differs';
      rec.detail = same ? null : 'the identity transform produced a different trace';
      continue;
    }
    if (o.error && t.error) {
      rec.verdict = 'not-executed';
      rec.detail = `neither region ran as a standalone statement (original: ${o.error}; rewritten: ${t.error})`;
    } else if (o.error) {
      rec.verdict = 'not-executed';
      rec.detail = `the ORIGINAL region did not run, so there is no baseline to compare against: ${o.error}`;
    } else if (t.error) {
      rec.verdict = 'sink-not-reached';
      rec.detail = `the rewritten region raised before reaching the sink: ${t.error}`;
    } else if (tt.length === 0 && ot.length === 0) {
      rec.verdict = 'no-sink-observed';
      rec.detail = 'neither region called anything: this payload has no observable sink in its own statement';
    } else if (tt.length === 0) {
      rec.verdict = 'sink-not-reached';
      rec.detail = 'the original region fired a sink and the rewritten one fired nothing';
    } else if (JSON.stringify(ot) === JSON.stringify(tt)) {
      // Naming the two apart matters: one observed the sink itself receive the
      // same value, the other only observed the region COMPUTE the same value,
      // with the sink on a later line the transform did not touch.
      const firedSink = tt.some((e) => !e.startsWith('bind '));
      rec.verdict = firedSink ? 'sink-equivalent' : 'value-equivalent';
      rec.detail = firedSink
        ? null
        : 'the region binds the payload value rather than calling a sink; the bound value is identical and the sink line lies outside the rewritten region';
    } else {
      rec.verdict = 'sink-divergent';
      rec.detail = 'the sink fired, but with a different callee or different argument values';
    }
  }
}

// ---------------------------------------------------------------------------
// Aggregate and write
// ---------------------------------------------------------------------------

/** Verdicts that demonstrate the vulnerability survived the rewrite. Everything
 *  else is, explicitly, a case where survival was NOT demonstrated. */
const DEMONSTRATED = new Set(['sink-equivalent', 'value-equivalent', 'constructive-equivalent']);

const byFamily = {};
const byTransform = {};
const verdictCounts = {};
for (const r of prepared) {
  const f = (byFamily[r.family] ??= { mode: r.mode, pairs: 0, demonstrated: 0, verdicts: {} });
  f.pairs += 1;
  if (DEMONSTRATED.has(r.verdict)) f.demonstrated += 1;
  f.verdicts[r.verdict] = (f.verdicts[r.verdict] ?? 0) + 1;
  const t = (byTransform[r.transformId] ??= { pairs: 0, demonstrated: 0, verdicts: {} });
  t.pairs += 1;
  if (DEMONSTRATED.has(r.verdict)) t.demonstrated += 1;
  t.verdicts[r.verdict] = (t.verdicts[r.verdict] ?? 0) + 1;
  verdictCounts[r.verdict] = (verdictCounts[r.verdict] ?? 0) + 1;
}

const controls = prepared.filter((r) => r.control);
// A control whose region fires nothing neither confirms nor refutes the probe,
// so it is counted separately rather than scored as a failure.
const controlsUnexpected = controls.filter((r) => r.verdict.startsWith('control-unexpectedly')).length;
const controlsNotObserved = controls.filter((r) => r.verdict === 'control-not-observed').length;
const controlsHold = controlsUnexpected === 0;

function gitInfo() {
  try {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { stdio: 'pipe', encoding: 'utf8' }).trim();
    const porcelain = execFileSync('git', ['status', '--porcelain'], { stdio: 'pipe', encoding: 'utf8' });
    const paths = porcelain.split('\n').map((l) => l.slice(3).trim()).filter(Boolean).sort();
    return { gitSha: sha, dirty: paths.length > 0, dirtyPaths: paths, dirtyProduct: paths.filter((p) => p.startsWith('packages/')) };
  } catch {
    // null, never false: "git was unavailable" must not render as "verified clean".
    return { gitSha: null, dirty: null, dirtyPaths: null, dirtyProduct: null };
  }
}

let pythonVersion = null;
if (available.python) {
  try {
    pythonVersion = execFileSync('python', ['--version'], { stdio: 'pipe', encoding: 'utf8' }).trim();
  } catch { /* recorded as null */ }
}

const out = {
  generatedBy: 'sec-b1-poc.mjs',
  question:
    'Does the vulnerability still exist after the evasion rewrite? The generator gate only establishes that the rewritten file still parses.',
  method: {
    execute:
      'The payload statement region is run with every free name bound to a recording stand-in, so the sink is observed instead of performed. The rewritten region must produce the same call trace — same callee path, same argument values — as the original line.',
    constructive:
      'Concatenations are folded and escapes decoded, then every constant and name mentioned by the original payload line must still be mentioned by the rewritten region. A member name turned into a string counts as the same element.',
    regionRule:
      'The region is the payload line plus the maximal contiguous run of changed lines touching it, so a hoisted temporary or a wrapper is executed with the payload. A changed line elsewhere in the file (an aliased import) is handled by name normalization instead.',
    sandbox:
      'No real sink runs: shells, deserializers, interpreters and I/O all resolve to recorders. The only real callables exposed are pure builtins, of which getattr is load-bearing for dynamic member access.',
    nameNormalization: `Identifiers the transforms introduce (prefix ${VG_PREFIX}) are removed from both sides before comparison, and an import alias is mapped back to the name it aliases.`,
  },
  familyEvidence: FAMILY_MODE,
  familyByRule: FAMILY_BY_RULE,
  interpretersAvailable: available,
  pairsScored: prepared.length,
  demonstrated: prepared.filter((r) => DEMONSTRATED.has(r.verdict)).length,
  notDemonstrated: prepared.filter((r) => !DEMONSTRATED.has(r.verdict) && !r.control).length,
  controlsHold,
  controlsUnexpected,
  controlsNotObserved,
  verdictCounts,
  byFamily,
  byTransform,
  results: prepared.map((r) => ({
    pairId: r.pairId,
    transformId: r.transformId,
    ruleId: r.ruleId,
    family: r.family,
    mode: r.mode,
    language: r.language,
    control: r.control,
    regionLines: r.regionLines ?? null,
    verdict: r.verdict,
    detail: r.detail,
    origTrace: r.origTrace ?? null,
    transformedTrace: r.transformedTrace ?? null,
  })),
  provenance: {
    ...gitInfo(),
    dirtyNote:
      'dirtyProduct lists the subset under packages/ — the only paths that can change what the analyzer reports. A dirty harness script is a different kind of dirty from a dirty analyzer.',
    nodeVersion: process.version,
    pythonVersion,
    manifest: MANIFEST,
    corpus: manifest.provenance ?? null,
    corpusProvenanceNote: manifest.provenance
      ? 'copied verbatim from the corpus manifest; this script does not regenerate the corpus'
      : 'the corpus manifest carried no provenance block',
    generatedAt: new Date().toISOString(),
  },
};

// Self-check: every pair must have carried a verdict out of the scoring, and no
// pair may be scored by a mode its family did not declare. A silently null
// verdict would be counted as "not demonstrated" and look like an honest
// negative, which is worse than a crash.
const unscored = prepared.filter((r) => r.verdict == null);
if (unscored.length) {
  console.error(`internal fault: ${unscored.length} pair(s) left unscored, e.g. ${unscored[0].pairId}`);
  process.exit(1);
}
const totalByFamily = Object.values(byFamily).reduce((a, f) => a + f.pairs, 0);
if (totalByFamily !== prepared.length) {
  console.error(`internal fault: family totals ${totalByFamily} != ${prepared.length} pairs`);
  process.exit(1);
}

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
console.log('\n# Evasion PoC — does the vulnerability survive the rewrite?\n');
console.log(`interpreters available: ${JSON.stringify(available)}`);
console.log(`\nfamily                     mode          pairs  demonstrated  other verdicts`);
for (const [name, f] of Object.entries(byFamily).sort()) {
  const other = Object.entries(f.verdicts)
    .filter(([v]) => !DEMONSTRATED.has(v))
    .sort()
    .map(([v, n]) => `${v}=${n}`)
    .join(' ');
  console.log(
    `${name.padEnd(26)} ${f.mode.padEnd(13)} ${String(f.pairs).padStart(5)} ${String(f.demonstrated).padStart(13)}  ${other}`,
  );
}
const declaredOnly = Object.entries(FAMILY_MODE).filter(([k]) => !byFamily[k]).map(([k]) => k);
if (declaredOnly.length) {
  console.log(`\nfamilies declared but not present in this corpus: ${declaredOnly.join(', ')}`);
}
console.log(`\nverdicts: ${JSON.stringify(verdictCounts)}`);
console.log(`negative controls: ${controls.length} total, ${controlsUnexpected} unexpected, ${controlsNotObserved} fired nothing (no observation)`);
console.log(`\nsurvival demonstrated for ${out.demonstrated}/${out.pairsScored} pairs; NOT demonstrated for ${out.notDemonstrated} (controls excluded).`);
console.log(`\nwrote ${OUT}`);
