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
 * @param {object} a
 * @param {object} a.elf                parsed artefact
 * @param {object|null} a.baseline      baseline record for the *matching* key, or null
 * @param {string|null} a.baselineState 'matched' | 'key-mismatch' | 'absent'
 * @param {object} a.source             { available, identifiers:Set, sourceBasenames:Set }
 * @param {object} a.libs               { available, index:Map<name,string[]>, missing:string[], allowed:Set|null }
 * @param {string[]} a.flags            normalised flag list from the baseline key
 */
export function classifyArtifact(a) {
  const { elf, baseline, baselineState, source, libs, flags } = a;

  const baselineSets = baseline
    ? {
        defined: new Set(baseline.defined.map((d) => d.name)),
        undef: new Set(baseline.undefined),
        sections: new Set(baseline.sections.map((s) => s.name)),
        init: new Set(baseline.initArrays.map((e) => `${e.array}|${e.target}`)),
      }
    : null;

  const definedIndex = new Map();
  for (const s of definedSymbols(elf)) definedIndex.set(stripVersion(s.name).base, s);
  const sectionNames = new Set(elf.sections.map((s) => s.name));

  const sanitizerRequested = flags.some((f) => /^-fsanitize/.test(f));

  // ---- rules over a defined symbol ---------------------------------------

  function ruleBaselineDefined(item) {
    if (!baselineSets) return UNAVAILABLE('baseline-literal', baselineState === 'key-mismatch' ? 'no baseline for this (toolchain, flags, link form)' : 'no baseline recorded');
    const n = item.name;
    if (baselineSets.defined.has(n)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: n });
    const v = stripVersion(n).base;
    if (v !== n && baselineSets.defined.has(v)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: v });
    return NOMATCH;
  }

  function ruleLinkerSynthesised(item) {
    const n = stripVersion(item.name).base;
    if (LINKER_SYNTHESISED.has(n)) return MATCH('linker-generated', 'linker-synthesised-name', { symbol: n });
    const info = item.nameInfo;
    if (info.kind === 'encapsulation-symbol') {
      // `__start_foo` / `__stop_foo` are synthesised by the linker only for a
      // section that exists and whose name is a C identifier. Requiring the
      // section to be present is what stops this from being a free pass for any
      // symbol that happens to begin `__start_`.
      if (sectionNames.has(info.encapsulates)) {
        return MATCH('linker-generated', 'section-encapsulation-symbol', { section: info.encapsulates });
      }
      return NOMATCH;
    }
    return NOMATCH;
  }

  function ruleRuntimeSupportName(item) {
    const n = stripVersion(item.name).base;
    const info = item.nameInfo;
    if (info.kind === 'eh-except-table') {
      return MATCH('runtime-support', 'eh-except-table', { note: 'landing-pad table emitted with the function it belongs to' });
    }
    if (info.kind === 'eh-personality-ref') {
      if (definedIndex.has(info.references) || elf.symtab.some((s) => stripVersion(s.name).base === info.references)) {
        return MATCH('runtime-support', 'eh-personality-reference', { references: info.references });
      }
      return NOMATCH;
    }
    if (info.kind === 'sanitizer-odr-indicator') {
      if (!sanitizerRequested) return NOMATCH;
      // The indicator names the global it guards. Requiring that global to be
      // present ties the instrumentation to something the source produced.
      if (definedIndex.has(info.references)) {
        return MATCH('runtime-support', 'sanitizer-odr-indicator', { guards: info.references });
      }
      return NOMATCH;
    }
    if (info.kind === 'sanitizer-module-init') {
      if (!sanitizerRequested) return NOMATCH;
      return MATCH('runtime-support', 'sanitizer-module-init', { sanitizer: info.sanitizer });
    }
    for (const r of RUNTIME_SUPPORT) {
      if (!r.re.test(n)) continue;
      if (r.requiresFlag && !flags.some((f) => r.requiresFlag.test(f))) {
        // The name looks like runtime support, but nothing on the command line
        // asked for that runtime. Falling through here is deliberate: an
        // unrequested __asan_* in a build with no sanitiser is the finding.
        continue;
      }
      return MATCH('runtime-support', 'runtime-support-name', { family: r.family, requiredFlag: r.requiresFlag ? String(r.requiresFlag) : null });
    }
    return NOMATCH;
  }

  function sourceAttributable(info) {
    if (!source.available) return { ok: null };
    const { needSource, abi } = attributableComponents(info);
    const missing = needSource.filter((c) => !source.identifiers.has(c) && !source.identifiers.has(stripOptimiserSuffix(c).base));
    return { ok: missing.length === 0, missing, abi, checked: needSource };
  }

  function ruleGeneratorDerived(item) {
    const info = item.nameInfo;
    const generated = new Set([
      'vtable', 'vtt', 'typeinfo', 'typeinfo-name', 'construction-vtable',
      'thunk-non-virtual', 'thunk-virtual', 'thunk-covariant',
      'guard-variable', 'reference-temporary',
      'static-init-ctor', 'static-init-dtor', 'static-init-var',
    ]);
    if (info.kind === 'static-init-ctor' || info.kind === 'static-init-dtor') {
      if (!source.available) return UNAVAILABLE('generator-derived', 'no preprocessed source universe');
      // `_GLOBAL__sub_I_<file>` names the translation unit it initialises.
      // Requiring that file to be one of the declared sources is what keeps a
      // constructor smuggled in from an undeclared unit visible.
      if (source.sourceBasenames.has(info.originFile)) {
        return MATCH('generator-derived', 'static-initialiser-for-declared-source', { unit: info.originFile });
      }
      return NOMATCH;
    }
    if (info.kind === 'static-init-var') {
      return MATCH('generator-derived', 'static-initialiser-helper', { note: '__cxx_global_var_init' });
    }
    if (!info.mangled) return NOMATCH;
    if (!generated.has(info.kind) && !info.hasClosure && !info.hasTemplateArgs) return NOMATCH;
    const att = sourceAttributable(info);
    if (att.ok === null) return UNAVAILABLE('generator-derived', 'no preprocessed source universe');
    if (!att.ok) return NOMATCH;
    return MATCH('generator-derived', 'itanium-generated-entity', {
      construct: info.kind,
      closure: info.hasClosure ? 1 : 0,
      templateArgs: info.hasTemplateArgs ? 1 : 0,
      sourceNames: att.checked,
    });
  }

  function ruleSourceDerived(item) {
    const info = item.nameInfo;
    if (item.symbolType === 'FILE') {
      if (!source.available) return UNAVAILABLE('source-derived', 'no preprocessed source universe');
      if (source.sourceBasenames.has(stripVersion(item.name).base)) {
        return MATCH('source-derived', 'stt-file-names-declared-source', { unit: item.name });
      }
      return NOMATCH;
    }
    if (!source.available) return UNAVAILABLE('source-derived', 'no preprocessed source universe');
    if (info.mangled) {
      const att = sourceAttributable(info);
      if (att.ok === null) return UNAVAILABLE('source-derived', 'no preprocessed source universe');
      if (att.ok && info.components.length > 0) {
        return MATCH('source-derived', 'mangled-name-fully-attributed', { sourceNames: att.checked, optimiserSuffixes: info.optimiserSuffixes });
      }
      return NOMATCH;
    }
    const base = stripOptimiserSuffix(stripVersion(item.name).base).base;
    if (source.identifiers.has(base)) {
      return MATCH('source-derived', 'unmangled-name-in-translation-unit', { identifier: base, optimiserSuffixes: info.optimiserSuffixes });
    }
    return NOMATCH;
  }

  // ---- rules over an undefined symbol ------------------------------------

  function ruleBaselineUndefined(item) {
    if (!baselineSets) return UNAVAILABLE('baseline-literal', baselineState === 'key-mismatch' ? 'no baseline for this (toolchain, flags, link form)' : 'no baseline recorded');
    if (baselineSets.undef.has(item.name)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: item.name });
    const v = stripVersion(item.name).base;
    if (baselineSets.undef.has(v)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSymbol: v });
    return NOMATCH;
  }

  function ruleDependencyResolved(item) {
    if (!libs.available) return UNAVAILABLE('dependency-resolution', `needed libraries not located: ${libs.missing.join(', ')}`);
    const n = stripVersion(item.name).base;
    const providers = libs.index.get(n);
    if (!providers || providers.length === 0) return NOMATCH;
    const allowed = libs.allowed ? providers.filter((p) => libs.allowed.has(p)) : providers;
    if (allowed.length === 0) {
      // It resolves, but only in a library the policy does not authorise. That
      // is a finding, not an explanation, so this returns no match rather than
      // an origin.
      return NOMATCH;
    }
    return MATCH('dependency-derived', 'resolved-in-needed-library', { providers: allowed.sort() });
  }

  function ruleWeakUnresolvable(item) {
    if (item.bind !== 'WEAK') return NOMATCH;
    if (!libs.available) return UNAVAILABLE('weak-undefined', 'needed libraries not located');
    // A weak undefined symbol that resolves nowhere is legal and common
    // (__gmon_start__, the _ITM_* pair). It is still not *explained* by
    // anything measured, so it is reported as Unresolved rather than waved
    // through — the baseline is where these are supposed to be accounted for.
    return UNAVAILABLE('weak-undefined', 'weak undefined symbol resolving in no needed library');
  }

  // ---- driver -------------------------------------------------------------

  function run(item, rules) {
    const unavailable = [];
    for (const rule of rules) {
      const r = rule(item);
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

  const definedRules = [ruleBaselineDefined, ruleLinkerSynthesised, ruleRuntimeSupportName, ruleGeneratorDerived, ruleSourceDerived];
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
  const undefinedRules = [ruleBaselineUndefined, ruleDependencyResolved, ruleRuntimeSupportName, ruleGeneratorDerived, ruleSourceDerived, ruleWeakUnresolvable];

  const items = [];

  for (const s of definedSymbols(elf)) {
    if (s.type === STT.SECTION) continue;
    const item = {
      kind: 'defined-symbol',
      name: s.name,
      bind: bindName(s.bind),
      symbolType: typeName(s.type),
      section: elf.sections[s.st_shndx]?.name ?? (s.st_shndx === SHN.ABS ? 'ABS' : `shndx${s.st_shndx}`),
      nameInfo: readName(s.name),
    };
    items.push(run(item, definedRules));
  }

  for (const s of undefinedSymbols(elf)) {
    const item = {
      kind: 'undefined-symbol',
      name: s.name,
      bind: bindName(s.bind),
      symbolType: typeName(s.type),
      section: null,
      nameInfo: readName(s.name),
    };
    items.push(run(item, undefinedRules));
  }

  // ---- sections -----------------------------------------------------------

  const explainedSymbolNames = new Set(items.filter((i) => i.verdict === 'Explained').map((i) => stripVersion(i.name).base));

  function ruleBaselineSection(item) {
    if (!baselineSets) return UNAVAILABLE('baseline-literal', baselineState === 'key-mismatch' ? 'no baseline for this (toolchain, flags, link form)' : 'no baseline recorded');
    if (baselineSets.sections.has(item.name)) return MATCH('toolchain-derived', 'baseline-literal', { baselineSection: item.name });
    return NOMATCH;
  }

  function ruleSectionGrammar(item) {
    const info = readSectionName(item.name);
    if (info.kind === 'abi-section') return MATCH('toolchain-derived', 'abi-section-name', { grammar: 'ELF/psABI section name' });
    if (info.kind === 'relocation-section') {
      if (sectionNames.has(info.appliesTo) || readSectionName(info.appliesTo).kind !== 'unknown') {
        return MATCH('linker-generated', 'relocation-section-for-known-section', { appliesTo: info.appliesTo });
      }
      return NOMATCH;
    }
    if (info.kind === 'abi-section-with-suffix') {
      if (explainedSymbolNames.has(info.suffix)) {
        return MATCH('generator-derived', 'comdat-section-for-explained-symbol', { parent: info.parent, symbol: info.suffix });
      }
      if (source.available && source.identifiers.has(info.suffix)) {
        return MATCH('source-derived', 'section-suffix-in-translation-unit', { parent: info.parent, suffix: info.suffix });
      }
      if (!source.available) return UNAVAILABLE('section-suffix', 'no preprocessed source universe');
      return NOMATCH;
    }
    if (info.kind === 'sanitizer-section') {
      if (!sanitizerRequested) return NOMATCH;
      return MATCH('runtime-support', 'sanitizer-section', { section: item.name });
    }
    return NOMATCH;
  }

  for (const sec of elf.sections) {
    if (sec.index === 0) continue;
    const item = {
      kind: 'section',
      name: sec.name,
      executable: (sec.sh_flags & SHF.EXECINSTR) !== 0 ? 1 : 0,
      writable: (sec.sh_flags & SHF.WRITE) !== 0 ? 1 : 0,
      alloc: (sec.sh_flags & SHF.ALLOC) !== 0 ? 1 : 0,
      sectionType: sec.sh_type,
      size: sec.sh_size,
      nameInfo: readName(sec.name ?? ''),
    };
    items.push(run(item, [ruleBaselineSection, ruleSectionGrammar]));
  }

  // ---- initialiser array entries -----------------------------------------

  const itemByName = new Map();
  for (const i of items) if (i.kind === 'defined-symbol') itemByName.set(stripVersion(i.name).base, i);

  function ruleInitBaseline(item) {
    if (!baselineSets) return UNAVAILABLE('baseline-literal', baselineState === 'key-mismatch' ? 'no baseline for this (toolchain, flags, link form)' : 'no baseline recorded');
    if (item.target && baselineSets.init.has(`${item.array}|${item.target}`)) {
      return MATCH('toolchain-derived', 'baseline-literal', { array: item.array, target: item.target });
    }
    return NOMATCH;
  }

  function ruleInitFromGenerator(item) {
    if (item.target === null) {
      return UNAVAILABLE('init-target-resolution', `slot ${item.slot} of ${item.array} did not resolve to a symbol (${item.resolvedVia ?? 'no relocation and no matching st_value'})`);
    }
    const target = itemByName.get(item.target);
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
      const wants = item.array === '.fini_array' ? source.declaresDestructor : source.declaresConstructor;
      if (wants) {
        return MATCH('source-derived', 'source-declared-constructor-attribute', {
          target: item.target,
          granularity: 'translation-unit',
        });
      }
    }
    return NOMATCH;
  }

  for (const e of readInitArrays(elf)) {
    const item = {
      kind: 'init-array-entry',
      name: e.target ?? `${e.array}[${e.slot}]`,
      array: e.array,
      slot: e.slot,
      target: e.target,
      resolvedVia: e.resolvedVia,
      nameInfo: readName(e.target ?? ''),
    };
    items.push(run(item, [ruleInitBaseline, ruleInitFromGenerator]));
  }

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
