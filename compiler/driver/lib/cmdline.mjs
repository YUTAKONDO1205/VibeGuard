// Command-line normalisation.
//
// The flag checks downstream are only as good as this file. A check that reads
// the raw argv sees `-Xclang -load` as two unrelated tokens and `@build.rsp` as
// one, so a forbidden flag hidden behind either is a flag the policy never
// examined — which the driver would then report as a clean build. Everything
// here exists to make the set of tokens the policy is matched against the set
// of tokens clang will actually act on.
//
// Nothing here is passed to clang. The compiler is invoked with the caller's
// original argv (minus the driver's own flags) precisely so that normalisation
// bugs cannot change the emitted bytes; see invoke.mjs.

import { readFileSync } from 'node:fs';
import { basename, dirname, extname, resolve } from 'node:path';

// Flags whose value is the *next* token. Getting this list wrong in the
// permissive direction turns a flag's value into a phantom source file; getting
// it wrong in the strict direction hides a real source. Both are visible in the
// recorded `sources` list, which is why it is recorded.
export const SEPARATE_VALUE_FLAGS = new Set([
  '-o', '-I', '-isystem', '-iquote', '-idirafter', '-include', '-imacros',
  '-isysroot', '-D', '-U', '-L', '-l', '-MF', '-MT', '-MQ', '-MJ', '-x',
  '-target', '-Xclang', '-Xlinker', '-Xpreprocessor', '-Xassembler', '-Xarch',
  '-z', '-u', '-e', '-T', '-arch', '-mllvm', '-B', '-F', '-framework',
  '-install_name', '-rpath', '--sysroot', '-aux-info', '-iprefix',
  '-iwithprefix', '-iwithprefixbefore', '-isystem-after', '--config',
  '-serialize-diagnostics', '-dependency-file', '-index-store-path',
  '-bundle_loader', '-allowable_client', '-current_version',
  '-compatibility_version', '-filelist', '-weak_library', '-dylib_file',
  '--output', '-fmodule-file', '-fmodule-map-file',
]);

// Inputs that are compiled, versus inputs that are only linked. Both are
// recorded; only the first are `sources`.
const SOURCE_EXTENSIONS = new Set([
  '.c', '.i', '.ii', '.m', '.mi', '.mm', '.M', '.cc', '.cp', '.cpp', '.CPP',
  '.c++', '.cxx', '.cppm', '.C', '.cu', '.hip', '.s', '.S', '.sx', '.ll', '.bc',
  '.h', '.hh', '.hpp', '.hxx',
]);
const LINK_INPUT_EXTENSIONS = new Set(['.o', '.obj', '.a', '.so', '.lo', '.dylib', '.dll']);

export const OPT_LEVELS = new Set(['-O0', '-O1', '-O2', '-O3', '-Os', '-Oz']);

/**
 * Tokenise a response file the way llvm::cl::TokenizeGNUCommandLine does:
 * whitespace separates, single quotes group literally, double quotes group with
 * backslash escapes, and a bare backslash escapes the next character.
 *
 * Documented as an approximation of LLVM's lexer rather than a port of it. It
 * agrees on every form clang's own driver emits; where it could disagree is
 * pathological quoting, and a response file the driver cannot tokenise the same
 * way clang does is reported (see `notes`) rather than assumed harmless.
 */
export function tokenizeResponseFile(text) {
  const tokens = [];
  let cur = '';
  let has = false;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (/\s/.test(ch)) {
      if (has) { tokens.push(cur); cur = ''; has = false; }
      i += 1;
      continue;
    }
    if (ch === '\\') {
      if (i + 1 < n) { cur += text[i + 1]; has = true; i += 2; } else { i += 1; }
      continue;
    }
    if (ch === "'") {
      i += 1;
      has = true;
      while (i < n && text[i] !== "'") { cur += text[i]; i += 1; }
      i += 1;
      continue;
    }
    if (ch === '"') {
      i += 1;
      has = true;
      while (i < n && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < n) { cur += text[i + 1]; i += 2; } else { cur += text[i]; i += 1; }
      }
      i += 1;
      continue;
    }
    cur += ch;
    has = true;
    i += 1;
  }
  if (has) tokens.push(cur);
  return tokens;
}

const MAX_RESPONSE_DEPTH = 16;
const MAX_RESPONSE_TOKENS = 200000;

/**
 * Expand `@file` arguments recursively.
 *
 * @returns {{argv: string[], expanded: string[], notes: {kind: string, file: string, detail: string}[]}}
 *   `notes` is non-empty when an expansion could not be completed. The caller
 *   turns that into exit 3 — an unread response file is a part of the command
 *   line the policy was never matched against, and calling that clean is the
 *   failure mode this whole directory is about.
 */
export function expandResponseFiles(argv, { cwd, readFile = (p) => readFileSync(p, 'utf8') } = {}) {
  const out = [];
  const expanded = [];
  const notes = [];

  const walk = (tokens, baseDir, depth, chain) => {
    for (const tok of tokens) {
      if (typeof tok !== 'string' || !tok.startsWith('@') || tok.length === 1) {
        out.push(tok);
        continue;
      }
      const target = resolve(baseDir, tok.slice(1));
      if (depth >= MAX_RESPONSE_DEPTH) {
        notes.push({ kind: 'too-deep', file: tok, detail: `nesting exceeds ${MAX_RESPONSE_DEPTH}` });
        out.push(tok);
        continue;
      }
      if (chain.includes(target)) {
        notes.push({ kind: 'cycle', file: tok, detail: 'response file includes itself' });
        out.push(tok);
        continue;
      }
      let text;
      try {
        text = readFile(target);
      } catch (err) {
        // `err.message`, not `err.code`, is where an fs error keeps the
        // absolute path it failed on — and this note ends up in a finding, and
        // findings end up in the record, which may not carry one. The token as
        // the caller wrote it is already in `file`; the errno adds what the
        // token does not.
        notes.push({ kind: 'unreadable', file: tok, detail: err.code ?? 'read failed' });
        out.push(tok);
        continue;
      }
      expanded.push(tok);
      const inner = tokenizeResponseFile(text);
      if (out.length + inner.length > MAX_RESPONSE_TOKENS) {
        notes.push({ kind: 'too-large', file: tok, detail: `expansion exceeds ${MAX_RESPONSE_TOKENS} tokens` });
        continue;
      }
      walk(inner, dirname(target), depth + 1, [...chain, target]);
    }
  };

  walk(argv, cwd, 0, []);
  return { argv: out, expanded, notes };
}

function splitCommaList(value) {
  return value.split(',').filter((s) => s.length > 0);
}

/**
 * Normalise an already-response-file-expanded argv.
 *
 * The returned `matchSpace` is what flag policy is evaluated against. It holds
 * the driver-level tokens *and* the cc1-level tokens hiding behind `-Xclang`
 * and the linker tokens hiding behind `-Wl,`/`-Xlinker`, because a policy that
 * forbids `-load` means it whether or not the caller spelled it
 * `-Xclang -load`.
 */
export function normalise(argv, { mode = 'c' } = {}) {
  const tokens = [...argv];
  const driverTokens = [];
  const cc1Tokens = [];
  const linkerTokens = [];
  const sources = [];
  const linkInputs = [];
  const optLevels = [];
  const passPlugins = [];
  const frontendPlugins = [];
  const legacyLoads = [];
  const unpairedXclang = [];

  let output = null;
  let outputForm = null;
  let compileOnly = false;
  let assembleOnly = false;
  let preprocessOnly = false;
  let syntaxOnly = false;
  let xLang = null;
  let sawDashDash = false;

  const isFlag = (t) => t.length > 1 && t.startsWith('-') && !sawDashDash;

  for (let i = 0; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if (tok === '--') { sawDashDash = true; driverTokens.push(tok); continue; }

    if (!isFlag(tok)) {
      // A positional. `-` alone means stdin, which is a source.
      const ext = tok === '-' ? '.c' : extname(tok);
      if (xLang && xLang !== 'none') sources.push(tok);
      else if (SOURCE_EXTENSIONS.has(ext)) sources.push(tok);
      else if (LINK_INPUT_EXTENSIONS.has(ext) || /\.so(\.\d+)+$/.test(tok)) linkInputs.push(tok);
      else linkInputs.push(tok);
      continue;
    }

    driverTokens.push(tok);

    if (OPT_LEVELS.has(tok)) { optLevels.push(tok); continue; }
    if (tok === '-O') { optLevels.push('-O1'); continue; } // clang: bare -O is -O1
    if (tok === '-c') { compileOnly = true; continue; }
    if (tok === '-S') { assembleOnly = true; continue; }
    if (tok === '-E') { preprocessOnly = true; continue; }
    if (tok === '-fsyntax-only') { syntaxOnly = true; continue; }

    if (tok.startsWith('-fpass-plugin=')) { passPlugins.push(tok.slice('-fpass-plugin='.length)); continue; }
    if (tok.startsWith('-fplugin=')) { frontendPlugins.push(tok.slice('-fplugin='.length)); continue; }

    if (tok.startsWith('-Wl,')) {
      const parts = splitCommaList(tok.slice(4));
      linkerTokens.push(...parts);
      continue;
    }

    // Separate-value flags.
    if (SEPARATE_VALUE_FLAGS.has(tok)) {
      const value = i + 1 < tokens.length ? tokens[i + 1] : undefined;
      if (value === undefined) {
        if (tok === '-Xclang') unpairedXclang.push(tok);
        continue;
      }
      i += 1;
      driverTokens.push(value);
      switch (tok) {
        case '-o':
        case '--output':
          output = value; outputForm = 'separate'; break;
        case '-x':
          xLang = value; break;
        case '-Xclang':
          cc1Tokens.push(value);
          if (value === '-load') {
            // `-Xclang -load -Xclang <path>` — the legacy plugin mechanism.
            const nextIsXclang = tokens[i + 1] === '-Xclang';
            const path = nextIsXclang ? tokens[i + 2] : tokens[i + 1];
            if (typeof path === 'string') legacyLoads.push(path);
          }
          break;
        case '-Xlinker':
          linkerTokens.push(value); break;
        default:
          break;
      }
      continue;
    }

    // Joined forms.
    if (tok.startsWith('--output=')) { output = tok.slice('--output='.length); outputForm = 'joined'; continue; }
    if (tok.startsWith('-o') && tok.length > 2 && !tok.startsWith('-o=')) { output = tok.slice(2); outputForm = 'joined'; continue; }
    if (tok.startsWith('-x') && tok.length > 2) { xLang = tok.slice(2); continue; }
  }

  const action = preprocessOnly ? 'preprocess'
    : syntaxOnly ? 'syntax-only'
      : assembleOnly ? 'assemble'
        : compileOnly ? 'compile'
          : 'link';

  const matchSpace = [...driverTokens, ...cc1Tokens, ...linkerTokens];

  return {
    mode,
    action,
    argv: tokens,
    driverTokens,
    cc1Tokens,
    linkerTokens,
    matchSpace,
    sources,
    linkInputs,
    optLevels,
    output,
    outputForm,
    xLang,
    plugins: { pass: passPlugins, frontend: frontendPlugins, legacyLoad: legacyLoads },
    unpairedXclang,
    expectedArtifacts: expectedArtifacts({ action, output, sources }),
  };
}

/**
 * What clang will write, so the record can digest it. Derived from the same
 * rules clang uses: `-o` wins; otherwise `-c`/`-S` name one output per input in
 * the working directory, and a link with no `-o` is `a.out`.
 */
/**
 * What `CCC_OVERRIDE_OPTIONS` adds to, or takes away from, the command line.
 *
 * clang edits its own argument list from this variable before it does anything
 * else, so a check that reads only argv is checking a command line that was not
 * the one compiled. Measured: `CCC_OVERRIDE_OPTIONS='+-O0'` on a `-O2`
 * invocation produces an object byte-identical to a plain `-O0` build, and a
 * flag check blind to it reports the level it was asked for rather than the one
 * that ran.
 *
 * `+X` appends and `^X` prepends, and both are recoverable: the token is right
 * there. `s/X/Y/`, `xX` and `XX` rewrite or delete arguments, and what they
 * leave behind cannot be known without replaying clang's own edit — so their
 * presence makes the parse **incomplete** rather than clean. The peer plugin
 * check already draws that line; this draws the same one for flags, from the
 * same reading of the same variable.
 */
export function parseOverrideEnv(value) {
  const out = { prepend: [], append: [], opaque: false, present: false };
  if (typeof value !== 'string' || value.trim() === '') return out;
  out.present = true;
  for (const tok of value.trim().split(/\s+/).filter(Boolean)) {
    if (tok.startsWith('+')) { out.append.push(tok.slice(1)); continue; }
    if (tok.startsWith('^')) { out.prepend.push(tok.slice(1)); continue; }
    if (tok.startsWith('s/') || tok.startsWith('x') || tok.startsWith('X')) { out.opaque = true; continue; }
    // An unrecognised operator is not a token we can place, and guessing where
    // it lands is how a check goes quietly wrong.
    out.opaque = true;
  }
  return out;
}

export function expectedArtifacts({ action, output, sources }) {
  if (action === 'preprocess' || action === 'syntax-only') return output ? [output] : [];
  if (output) return [output];
  if (action === 'link') return ['a.out'];
  const ext = action === 'assemble' ? '.s' : '.o';
  return sources.map((s) => basename(s, extname(s)) + ext);
}

/** Tokens the driver consumes itself and never forwards to clang. */
export const DRIVER_FLAGS = {
  '--policy': 1,
  '--vg-clang': 1,
  // The property observer `policy.fallback` needs. Consumed only when the policy
  // enables fallback; on its own it changes nothing. See lib/fallback.mjs.
  '--vg-observer': 1,
  '--vg-observe-pipeline': 0,
  '--vg-verbose': 0,
  '--vg-print-normalised': 0,
};

/**
 * Split the process argv into the driver's own options and the compiler's.
 * `compilerArgv` keeps the caller's original spelling — response files stay
 * unexpanded, joined forms stay joined — so that what clang sees is what the
 * caller wrote.
 */
export function splitDriverArgs(argv) {
  const own = {
    policy: null, clang: null, observer: null, observePipeline: false, verbose: false, printNormalised: false,
  };
  const compilerArgv = [];
  const errors = [];
  // Everything after a bare `--` belongs to the compiler, including tokens that
  // are spelled like this driver's own flags.
  //
  // Without this the split is position-blind, and since the last occurrence of
  // `--policy` wins, a caller could name a strict policy and then substitute a
  // permissive one from inside what is supposed to be the compiler's own
  // argument list. Measured before the fix, against a checkout of the released
  // tree: `--policy strict.json -- --policy weak.json -O2 -c hello.c` wrote its
  // evidence into the directory named by weak.json and none into the one named
  // by strict.json. The governing policy had been replaced by a token the
  // driver was told not to interpret.
  //
  // The consequence was not the one an audit had predicted — the run exited 1
  // and produced no artefact, because the tokens the driver consumed then went
  // missing from the compiler's line — but "the attack is currently clumsy" is
  // not a security property. What decides the policy must not be reachable from
  // the region the caller was promised would be passed through untouched.
  //
  // The lexer at the top of this file already treats `--` this way, so before
  // this change the two halves of the command line disagreed about where the
  // driver's own arguments stop.
  let sawDashDash = false;
  for (let i = 0; i < argv.length; i += 1) {
    const tok = argv[i];
    if (sawDashDash) { compilerArgv.push(tok); continue; }
    if (tok === '--') { sawDashDash = true; compilerArgv.push(tok); continue; }
    if (!Object.prototype.hasOwnProperty.call(DRIVER_FLAGS, tok)) {
      if (tok.startsWith('--policy=')) { own.policy = tok.slice('--policy='.length); continue; }
      if (tok.startsWith('--vg-clang=')) { own.clang = tok.slice('--vg-clang='.length); continue; }
      if (tok.startsWith('--vg-observer=')) { own.observer = tok.slice('--vg-observer='.length); continue; }
      compilerArgv.push(tok);
      continue;
    }
    const arity = DRIVER_FLAGS[tok];
    if (arity === 1) {
      const value = argv[i + 1];
      if (value === undefined) { errors.push(`${tok} requires a value`); continue; }
      i += 1;
      if (tok === '--policy') own.policy = value;
      if (tok === '--vg-clang') own.clang = value;
      if (tok === '--vg-observer') own.observer = value;
      continue;
    }
    if (tok === '--vg-observe-pipeline') own.observePipeline = true;
    if (tok === '--vg-verbose') own.verbose = true;
    if (tok === '--vg-print-normalised') own.printNormalised = true;
  }
  return { own, compilerArgv, errors };
}
