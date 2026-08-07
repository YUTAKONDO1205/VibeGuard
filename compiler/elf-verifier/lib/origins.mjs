// Origin classification: for each thing an artefact contains, which permitted
// origin accounts for it.
//
// THE ONE RULE THAT MATTERS
//
// A rule that could not run is not a rule that found nothing. Every rule below
// returns one of three things — matched, did-not-match, or could-not-run — and
// an item that no rule matched is Unexplained only if no rule *could not run*.
// Otherwise it is Unresolved. Collapsing those two is how a checker starts
// reporting "clean" for artefacts it never managed to look at, and it is also
// how a missing baseline turns into a wall of false positives; both failure
// modes come from the same collapse, in opposite directions.
//
// Rule order is strongest-evidence-first: a measured baseline beats a name
// grammar, and a symbol that genuinely resolves in a library on disk beats a
// name that merely looks like a runtime import.

import { STB, STT, SHN, SHF, definedSymbols, undefinedSymbols, readInitArrays, neededLibraries, bindName, typeName } from './elf.mjs';
import { readName, readSectionName, attributableComponents, LINKER_SYNTHESISED, RUNTIME_SUPPORT, stripVersion, stripOptimiserSuffix } from './names.mjs';

export const ORIGINS = [
  'source-derived',
  'generator-derived',
  'dependency-derived',
  'toolchain-derived',
  'linker-generated',
  'runtime-support',
];

const MATCH = (origin, rule, evidence) => ({ status: 'matched', origin, rule, evidence });
const NOMATCH = null;
const UNAVAILABLE = (rule, reason) => ({ status: 'unavailable', rule, reason });

/**
 * Everything the rules read, measured once.
 *
 * The rules below used to be closures declared inside `classifyArtifact`, which
 * made that function 355 lines: thirteen rules, four item loops and the driver,
 * in one body. Nothing about the rules required the nesting — they read the
 * artefact, the baseline, the source universe and the library index, and none of
 * them writes to any of it — so what the nesting bought was a function nobody
 * could read one rule of without scrolling past the other twelve.
 *
 * Two fields are filled in later than the rest, because they are derived from
 * items already classified: `explainedSymbolNames` before the sections are
 * classified, `itemByName` before the initialiser entries are. That ordering is
 * load-bearing and is now explicit in `classifyArtifact` rather than implied by
 * where a `const` happened to sit.
 */
function classificationContext({ elf, baseline, baselineState, source, libs, flags }) {
  const definedIndex = new Map();
  for (const s of definedSymbols(elf)) definedIndex.set(stripVersion(s.name).base, s);
  return {
    elf,
    baselineState,
    source,
    libs,
    flags,
    baselineSets: baseline
      ? {
          defined: new Set(baseline.defined.map((d) => d.name)),
          undef: new Set(baseline.undefined),
          sections: new Set(baseline.sections.map((s) => s.name)),
          init: new Set(baseline.initArrays.map((e) => `${e.array}|${e.target}`)),
        }
      : null,
    definedIndex,
    sectionNames: new Set(elf.sections.map((s) => s.name)),
    sanitizerRequested: flags.some((f) => /^-fsanitize/.test(f)),
    explainedSymbolNames: null,
    itemByName: null,
  };
}

/** Why no baseline could be consulted. The two reasons are not the same reason. */
function noBaseline(baselineState) {
  return UNAVAILABLE(
    'baseline-literal',
    baselineState === 'key-mismatch'
      ? 'no baseline for this (toolchain, flags, link form)'
      : 'no baseline recorded',
  );
}

// ---- rules over a defined symbol -------------------------------------------

function ruleBaselineDefined(ctx, item) {
  if (!ctx.baselineSets) return noBaseline(ctx.baselineState);
  const n = item.name;
  if (ctx.baselineSets.defined.has(n)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: n });
  const v = stripVersion(n).base;
  if (v !== n && ctx.baselineSets.defined.has(v)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: v });
  return NOMATCH;
}

function ruleLinkerSynthesised(ctx, item) {
  const n = stripVersion(item.name).base;
  if (LINKER_SYNTHESISED.has(n)) return MATCH('linker-generated', 'linker-synthesised-name', { symbol: n });
  const info = item.nameInfo;
  if (info.kind === 'encapsulation-symbol') {
    // `__start_foo` / `__stop_foo` are synthesised by the linker only for a
    // section that exists and whose name is a C identifier. Requiring the
    // section to be present is what stops this from being a free pass for any
    // symbol that happens to begin `__start_`.
    if (ctx.sectionNames.has(info.encapsulates)) {
      return MATCH('linker-generated', 'section-encapsulation-symbol', { section: info.encapsulates });
    }
    return NOMATCH;
  }
  return NOMATCH;
}

function ruleRuntimeSupportName(ctx, item) {
  const n = stripVersion(item.name).base;
  const info = item.nameInfo;
  if (info.kind === 'eh-except-table') {
    return MATCH('runtime-support', 'eh-except-table', { note: 'landing-pad table emitted with the function it belongs to' });
  }
  if (info.kind === 'eh-personality-ref') {
    if (ctx.definedIndex.has(info.references) || ctx.elf.symtab.some((s) => stripVersion(s.name).base === info.references)) {
      return MATCH('runtime-support', 'eh-personality-reference', { references: info.references });
    }
    return NOMATCH;
  }
  if (info.kind === 'sanitizer-odr-indicator') {
    if (!ctx.sanitizerRequested) return NOMATCH;
    // The indicator names the global it guards. Requiring that global to be
    // present ties the instrumentation to something the source produced.
    if (ctx.definedIndex.has(info.references)) {
      return MATCH('runtime-support', 'sanitizer-odr-indicator', { guards: info.references });
    }
    return NOMATCH;
  }
  if (info.kind === 'sanitizer-module-init') {
    if (!ctx.sanitizerRequested) return NOMATCH;
    return MATCH('runtime-support', 'sanitizer-module-init', { sanitizer: info.sanitizer });
  }
  for (const r of RUNTIME_SUPPORT) {
    if (!r.re.test(n)) continue;
    if (r.requiresFlag && !ctx.flags.some((f) => r.requiresFlag.test(f))) {
      // The name looks like runtime support, but nothing on the command line
      // asked for that runtime. Falling through here is deliberate: an
      // unrequested __asan_* in a build with no sanitiser is the finding.
      continue;
    }
    return MATCH('runtime-support', 'runtime-support-name', { family: r.family, requiredFlag: r.requiresFlag ? String(r.requiresFlag) : null });
  }
  return NOMATCH;
}

function sourceAttributable(ctx, info) {
  if (!ctx.source.available) return { ok: null };
  const { needSource, abi } = attributableComponents(info);
  const missing = needSource.filter((c) => !ctx.source.identifiers.has(c) && !ctx.source.identifiers.has(stripOptimiserSuffix(c).base));
  return { ok: missing.length === 0, missing, abi, checked: needSource };
}

/** Itanium constructs a generator emits without the source naming them directly. */
const GENERATED_KINDS = new Set([
  'vtable', 'vtt', 'typeinfo', 'typeinfo-name', 'construction-vtable',
  'thunk-non-virtual', 'thunk-virtual', 'thunk-covariant',
  'guard-variable', 'reference-temporary',
  'static-init-ctor', 'static-init-dtor', 'static-init-var',
]);

function ruleGeneratorDerived(ctx, item) {
  const info = item.nameInfo;
  if (info.kind === 'static-init-ctor' || info.kind === 'static-init-dtor') {
    if (!ctx.source.available) return UNAVAILABLE('generator-derived', 'no preprocessed source universe');
    // `_GLOBAL__sub_I_<file>` names the translation unit it initialises.
    // Requiring that file to be one of the declared sources is what keeps a
    // constructor smuggled in from an undeclared unit visible.
    if (ctx.source.sourceBasenames.has(info.originFile)) {
      return MATCH('generator-derived', 'static-initialiser-for-declared-source', { unit: info.originFile });
    }
    return NOMATCH;
  }
  if (info.kind === 'static-init-var') {
    return MATCH('generator-derived', 'static-initialiser-helper', { note: '__cxx_global_var_init' });
  }
  if (!info.mangled) return NOMATCH;
  if (!GENERATED_KINDS.has(info.kind) && !info.hasClosure && !info.hasTemplateArgs) return NOMATCH;
  const att = sourceAttributable(ctx, info);
  if (att.ok === null) return UNAVAILABLE('generator-derived', 'no preprocessed source universe');
  if (!att.ok) return NOMATCH;
  return MATCH('generator-derived', 'itanium-generated-entity', {
    construct: info.kind,
    closure: info.hasClosure ? 1 : 0,
    templateArgs: info.hasTemplateArgs ? 1 : 0,
    sourceNames: att.checked,
  });
}

function ruleSourceDerived(ctx, item) {
  const info = item.nameInfo;
  if (item.symbolType === 'FILE') {
    if (!ctx.source.available) return UNAVAILABLE('source-derived', 'no preprocessed source universe');
    if (ctx.source.sourceBasenames.has(stripVersion(item.name).base)) {
      return MATCH('source-derived', 'stt-file-names-declared-source', { unit: item.name });
    }
    return NOMATCH;
  }
  if (!ctx.source.available) return UNAVAILABLE('source-derived', 'no preprocessed source universe');
  if (info.mangled) {
    const att = sourceAttributable(ctx, info);
    if (att.ok === null) return UNAVAILABLE('source-derived', 'no preprocessed source universe');
    if (att.ok && info.components.length > 0) {
      return MATCH('source-derived', 'mangled-name-fully-attributed', { sourceNames: att.checked, optimiserSuffixes: info.optimiserSuffixes });
    }
    return NOMATCH;
  }
  const base = stripOptimiserSuffix(stripVersion(item.name).base).base;
  if (ctx.source.identifiers.has(base)) {
    return MATCH('source-derived', 'unmangled-name-in-translation-unit', { identifier: base, optimiserSuffixes: info.optimiserSuffixes });
  }
  return NOMATCH;
}

// ---- rules over an undefined symbol ----------------------------------------

function ruleBaselineUndefined(ctx, item) {
  if (!ctx.baselineSets) return noBaseline(ctx.baselineState);
  if (ctx.baselineSets.undef.has(item.name)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: item.name });
  const v = stripVersion(item.name).base;
  if (ctx.baselineSets.undef.has(v)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: v });
  return NOMATCH;
}

function ruleDependencyResolved(ctx, item) {
  if (!ctx.libs.available) return UNAVAILABLE('dependency-resolution', `needed libraries not located: ${ctx.libs.missing.join(', ')}`);
  const n = stripVersion(item.name).base;
  const providers = ctx.libs.index.get(n);
  if (!providers || providers.length === 0) return NOMATCH;
  const allowed = ctx.libs.allowed ? providers.filter((p) => ctx.libs.allowed.has(p)) : providers;
  if (allowed.length === 0) {
    // It resolves, but only in a library the policy does not authorise. That
    // is a finding, not an explanation, so this returns no match rather than
    // an origin.
    return NOMATCH;
  }
  return MATCH('dependency-derived', 'resolved-in-needed-library', { providers: allowed.sort() });
}

function ruleWeakUnresolvable(ctx, item) {
  if (item.bind !== 'WEAK') return NOMATCH;
  if (!ctx.libs.available) return UNAVAILABLE('weak-undefined', 'needed libraries not located');
  // A weak undefined symbol that resolves nowhere is legal and common
  // (__gmon_start__, the _ITM_* pair). It is still not *explained* by
  // anything measured, so it is reported as Unresolved rather than waved
  // through — the baseline is where these are supposed to be accounted for.
  return UNAVAILABLE('weak-undefined', 'weak undefined symbol resolving in no needed library');
}

// ---- rules over a section --------------------------------------------------

function ruleBaselineSection(ctx, item) {
  if (!ctx.baselineSets) return noBaseline(ctx.baselineState);
  if (ctx.baselineSets.sections.has(item.name)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSection: item.name });
  return NOMATCH;
}

function ruleSectionGrammar(ctx, item) {
  const info = readSectionName(item.name);
  if (info.kind === 'abi-section') return MATCH('toolchain-derived', 'abi-section-name', { grammar: 'ELF/psABI section name' });
  if (info.kind === 'relocation-section') {
    if (ctx.sectionNames.has(info.appliesTo) || readSectionName(info.appliesTo).kind !== 'unknown') {
      return MATCH('linker-generated', 'relocation-section-for-known-section', { appliesTo: info.appliesTo });
    }
    return NOMATCH;
  }
  if (info.kind === 'abi-section-with-suffix') {
    if (ctx.explainedSymbolNames.has(info.suffix)) {
      return MATCH('generator-derived', 'comdat-section-for-explained-symbol', { parent: info.parent, symbol: info.suffix });
    }
    if (ctx.source.available && ctx.source.identifiers.has(info.suffix)) {
      return MATCH('source-derived', 'section-suffix-in-translation-unit', { parent: info.parent, suffix: info.suffix });
    }
    if (!ctx.source.available) return UNAVAILABLE('section-suffix', 'no preprocessed source universe');
    return NOMATCH;
  }
  if (info.kind === 'sanitizer-section') {
    if (!ctx.sanitizerRequested) return NOMATCH;
    return MATCH('runtime-support', 'sanitizer-section', { section: item.name });
  }
  return NOMATCH;
}

// ---- rules over an initialiser array entry ---------------------------------

function ruleInitBaseline(ctx, item) {
  if (!ctx.baselineSets) return noBaseline(ctx.baselineState);
  if (item.target && ctx.baselineSets.init.has(`${item.array}|${item.target}`)) {
    return MATCH('toolchain-derived', 'baseline-literal', { array: item.array, target: item.target });
  }
  return NOMATCH;
}

function ruleInitFromGenerator(ctx, item) {
  if (item.target === null) {
    return UNAVAILABLE('init-target-resolution', `slot ${item.slot} of ${item.array} did not resolve to a symbol (${item.resolvedVia ?? 'no relocation and no matching st_value'})`);
  }
  const target = ctx.itemByName.get(item.target);
  if (!target) return UNAVAILABLE('init-target-resolution', `target ${item.target} is not a defined symbol in this artefact`);
  if (target.verdict === 'Unresolved') return UNAVAILABLE('init-target-classification', `target ${item.target} is itself Unresolved`);
  if (target.verdict !== 'Explained') return NOMATCH;
  // Being an explained symbol is not enough to be an explained *initialiser*.
  // Putting an otherwise ordinary function into .init_array is the whole
  // attack, so the entry has to be something whose job is to initialise.
  const k = target.nameInfo.kind;
  if (k === 'static-init-ctor' || k === 'static-init-dtor' || k === 'static-init-var') {
    return MATCH('generator-derived', 'initialiser-is-a-static-initialiser', { target: item.target, construct: k });
  }
  if (k === 'sanitizer-module-init') {
    return MATCH('runtime-support', 'initialiser-is-a-sanitizer-module-init', { target: item.target });
  }
  if (target.origin === 'source-derived') {
    const wants = item.array === '.fini_array' ? ctx.source.declaresDestructor : ctx.source.declaresConstructor;
    if (wants) {
      return MATCH('source-derived', 'source-declared-constructor-attribute', {
        target: item.target,
        granularity: 'translation-unit',
      });
    }
  }
  return NOMATCH;
}

// ---- rule chains, strongest evidence first ---------------------------------

const DEFINED_RULES = [ruleBaselineDefined, ruleLinkerSynthesised, ruleRuntimeSupportName, ruleGeneratorDerived, ruleSourceDerived];
// `ruleSourceDerived` is on this chain too, and its absence was a false
// accusation with a very ordinary trigger: a C file that declares a function
// defined in another translation unit and calls it. The symbol is undefined in
// the object, no library resolves it because there is no link yet, and nothing
// on the chain could say "the source asked for this" -- so an unremarkable
// two-file C program reported VG-INTRO-002 against its own call. The negative
// controls did not catch it because every one of them is a linked C++
// executable, where libstdc++ resolves what the source names.
//
// It goes last, after the dependency rule, so a symbol a permitted library
// does resolve is still attributed to that library rather than to the source
// that happened to name it.
const UNDEFINED_RULES = [ruleBaselineUndefined, ruleDependencyResolved, ruleRuntimeSupportName, ruleGeneratorDerived, ruleSourceDerived, ruleWeakUnresolvable];
const SECTION_RULES = [ruleBaselineSection, ruleSectionGrammar];
const INIT_RULES = [ruleInitBaseline, ruleInitFromGenerator];

// ---- driver ----------------------------------------------------------------

/**
 * Run `item` down `rules` and settle it. THE ONE RULE THAT MATTERS lives here:
 * an item no rule matched is Unexplained only when no rule reported that it
 * could not run. Otherwise it is Unresolved.
 */
function run(ctx, item, rules) {
  const unavailable = [];
  for (const rule of rules) {
    const r = rule(ctx, item);
    if (r === NOMATCH || r === undefined) continue;
    if (r.status === 'unavailable') {
      unavailable.push({ rule: r.rule, reason: r.reason });
      continue;
    }
    return { ...item, verdict: 'Explained', origin: r.origin, rule: r.rule, evidence: r.evidence };
  }
  if (unavailable.length > 0) {
    return { ...item, verdict: 'Unresolved', origin: null, rule: null, unavailableRules: unavailable };
  }
  return { ...item, verdict: 'Unexplained', origin: null, rule: null, unavailableRules: [] };
}

function definedSymbolItems(elf) {
  const out = [];
  for (const s of definedSymbols(elf)) {
    if (s.type === STT.SECTION) continue;
    out.push({
      kind: 'defined-symbol',
      name: s.name,
      bind: bindName(s.bind),
      symbolType: typeName(s.type),
      section: elf.sections[s.st_shndx]?.name ?? (s.st_shndx === SHN.ABS ? 'ABS' : `shndx${s.st_shndx}`),
      nameInfo: readName(s.name),
    });
  }
  return out;
}

function undefinedSymbolItems(elf) {
  return undefinedSymbols(elf).map((s) => ({
    kind: 'undefined-symbol',
    name: s.name,
    bind: bindName(s.bind),
    symbolType: typeName(s.type),
    section: null,
    nameInfo: readName(s.name),
  }));
}

function sectionItems(elf) {
  const out = [];
  for (const sec of elf.sections) {
    if (sec.index === 0) continue;
    out.push({
      kind: 'section',
      name: sec.name,
      executable: (sec.sh_flags & SHF.EXECINSTR) !== 0 ? 1 : 0,
      writable: (sec.sh_flags & SHF.WRITE) !== 0 ? 1 : 0,
      alloc: (sec.sh_flags & SHF.ALLOC) !== 0 ? 1 : 0,
      sectionType: sec.sh_type,
      size: sec.sh_size,
      nameInfo: readName(sec.name ?? ''),
    });
  }
  return out;
}

function initArrayItems(elf) {
  return readInitArrays(elf).map((e) => ({
    kind: 'init-array-entry',
    name: e.target ?? `${e.array}[${e.slot}]`,
    array: e.array,
    slot: e.slot,
    target: e.target,
    resolvedVia: e.resolvedVia,
    nameInfo: readName(e.target ?? ''),
  }));
}

/**
 * @param {object} a
 * @param {object} a.elf                parsed artefact
 * @param {object|null} a.baseline      baseline record for the *matching* key, or null
 * @param {string|null} a.baselineState 'matched' | 'key-mismatch' | 'absent'
 * @param {object} a.source             { available, identifiers:Set, sourceBasenames:Set }
 * @param {object} a.libs               { available, index:Map<name,string[]>, missing:string[], allowed:Set|null }
 * @param {string[]} a.flags            normalised flag list from the baseline key
 */
export function classifyArtifact(a) {
  const ctx = classificationContext(a);
  const { elf } = ctx;
  const items = [];

  for (const item of definedSymbolItems(elf)) items.push(run(ctx, item, DEFINED_RULES));
  for (const item of undefinedSymbolItems(elf)) items.push(run(ctx, item, UNDEFINED_RULES));

  // A COMDAT section is explained by the symbol it belongs to, so the sections
  // cannot be classified until the symbols have been.
  ctx.explainedSymbolNames = new Set(items.filter((i) => i.verdict === 'Explained').map((i) => stripVersion(i.name).base));
  for (const item of sectionItems(elf)) items.push(run(ctx, item, SECTION_RULES));

  // Likewise an initialiser entry is explained by what it points at, which has
  // to have been classified already for `ruleInitFromGenerator` to read it.
  ctx.itemByName = new Map();
  for (const i of items) if (i.kind === 'defined-symbol') ctx.itemByName.set(stripVersion(i.name).base, i);
  for (const item of initArrayItems(elf)) items.push(run(ctx, item, INIT_RULES));

  return { items, needed: neededLibraries(elf) };
}

/** Findings, in the shape compiler/schema/interfaces.md section 2 fixes. */
export function findingsFor(items, artefactPath) {
  const where = (kind) => ({ kind, path: artefactPath, unit: null, pass: null });
  const out = [];
  for (const i of items) {
    if (i.verdict !== 'Unexplained') continue;
    if (i.kind === 'defined-symbol') {
      out.push({
        id: 'VG-INTRO-001',
        severity: 'high',
        title: 'A symbol is present that no permitted origin explains',
        detail: `${i.name} (${i.bind}/${i.symbolType}, section ${i.section}) is defined in the artefact. It is not in the toolchain baseline for this (toolchain, flags, link form), it is not linker-synthesised, it is not runtime support the flags asked for, and none of its source-name components appear in the preprocessed translation unit.`,
        where: where('artifact'),
      });
    } else if (i.kind === 'undefined-symbol') {
      out.push({
        id: 'VG-INTRO-002',
        severity: 'high',
        title: 'An external call is made that the policy does not authorise',
        detail: `${i.name} (${i.bind}) is undefined and resolves in no authorised library on DT_NEEDED.`,
        where: where('link'),
      });
    } else if (i.kind === 'init-array-entry') {
      out.push({
        id: 'VG-INTRO-003',
        severity: 'critical',
        title: 'An initialiser runs that no permitted origin explains',
        detail: `${i.array} slot ${i.slot} runs ${i.target ?? 'an unresolved target'} before main. Resolved via ${i.resolvedVia ?? 'nothing'}.`,
        where: where('artifact'),
      });
    } else if (i.kind === 'section') {
      out.push({
        id: i.executable ? 'VG-INTRO-004' : 'VG-INTRO-001',
        severity: i.executable ? 'critical' : 'medium',
        title: i.executable
          ? 'An executable section is present that no permitted origin explains'
          : 'A section is present that no permitted origin explains',
        detail: `section ${i.name} (type ${i.sectionType}, ${i.size} bytes, executable=${i.executable})`,
        where: where('artifact'),
      });
    }
  }
  return out;
}

export function summarise(items) {
  const byVerdict = { Explained: 0, Unexplained: 0, Unresolved: 0 };
  const byOrigin = Object.fromEntries(ORIGINS.map((o) => [o, 0]));
  const byKind = {};
  for (const i of items) {
    byVerdict[i.verdict] = (byVerdict[i.verdict] ?? 0) + 1;
    if (i.origin) byOrigin[i.origin] = (byOrigin[i.origin] ?? 0) + 1;
    byKind[i.kind] = byKind[i.kind] ?? { Explained: 0, Unexplained: 0, Unresolved: 0 };
    byKind[i.kind][i.verdict]++;
  }
  return { byVerdict, byOrigin, byKind, total: items.length };
}
