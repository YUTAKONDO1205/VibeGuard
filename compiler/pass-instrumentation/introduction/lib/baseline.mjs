// Baseline subtraction: the step that has to happen before the detector, or
// the detector is a machine for accusing the compiler of its own work.
//
// The subtraction is `introduced - explained`, and everything interesting is in
// how `explained` is built. Two halves, described at the top of origins.mjs:
// the measured front-end set for this exact compilation, and the structural
// rules for names whose shape the ABI or LLVM defines.
//
// One ordering detail is load-bearing and is why this is a module rather than a
// map() call. Executable sections cannot be classified until the symbols inside
// them have been: `.text._ZNSt6vectorIiSaIiEED2Ev` is fine because the template
// instantiation it holds is fine, and `.text.intro_injected` is not, because
// the symbol it holds is not. So symbols are classified first, and the section
// pass reads their verdicts. A single pass would have to decide sections on
// their names alone, which is the rule that a section named `.text.something`
// defeats in one line.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { classifyOrigin, emptyContext, summariseVerdicts } from './origins.mjs';
import { STANDARD_EXEC_SECTIONS } from './elf.mjs';

/**
 * @param {object[]} elements  from `objectElements`, or built by a caller
 * @param {import('./origins.mjs').OriginContext} ctx
 */
export function subtractBaseline(elements, ctx = emptyContext()) {
  const symbolVerdict = new Map();
  const classified = [];

  // Pass 1: everything that is not a section.
  for (const el of elements) {
    if (el.kind === 'section') continue;
    const c = classifyOrigin(el, ctx);
    const row = { ...el, ...c };
    classified.push(row);
    if (el.kind === 'symbol') symbolVerdict.set(el.name, row);
  }

  // Pass 2: executable sections, decided by what they hold.
  for (const el of elements) {
    if (el.kind !== 'section') continue;
    classified.push({ ...el, ...classifySection(el, symbolVerdict) });
  }

  return { classified, ...summariseVerdicts(classified) };
}

/**
 * An executable section is explained when it is one the toolchain always
 * produces, or when everything defined inside it is explained.
 *
 * The second clause is the one that matters. A build with -ffunction-sections
 * produces one `.text.<mangled name>` per function -- fifty-one of them on this
 * component's negative fixture -- and a rule that only knew the standard names
 * would report every one of them. The section itself carries no risk beyond its
 * contents, so its verdict is its contents' verdict.
 */
export function classifySection(el, symbolVerdict) {
  if (STANDARD_EXEC_SECTIONS.has(el.name)) {
    return {
      origin: 'toolchain-derived',
      verdict: 'Explained',
      rule: 'S1.standard-section',
      reason: 'a section every build of this toolchain produces',
    };
  }

  const contained = el.detail?.contains ?? [];
  if (contained.length === 0) {
    return {
      origin: null,
      verdict: 'Unresolved',
      rule: 'S3.empty-section',
      reason: 'an executable section holding no symbol this reader could name, so what '
        + 'it contains was not established',
    };
  }

  const unexplained = [];
  const unresolved = [];
  for (const name of contained) {
    const v = symbolVerdict.get(name);
    if (!v) { unresolved.push(name); continue; }
    if (v.verdict === 'Unexplained') unexplained.push(name);
    else if (v.verdict === 'Unresolved') unresolved.push(name);
  }

  if (unexplained.length > 0) {
    return {
      origin: null,
      verdict: 'Unexplained',
      rule: 'S4.unexplained-contents',
      reason: `an executable section outside the standard set, holding ${unexplained.length} `
        + `symbol(s) that no permitted origin explains: ${unexplained.join(', ')}`,
    };
  }
  if (unresolved.length > 0) {
    return {
      origin: null,
      verdict: 'Unresolved',
      rule: 'S5.unresolved-contents',
      reason: `the verdict on ${unresolved.join(', ')} could not be decided, so neither `
        + 'could the verdict on the section holding them',
    };
  }
  return {
    origin: 'toolchain-derived',
    verdict: 'Explained',
    rule: 'S2.explained-contents',
    reason: `everything defined in this section is explained (${contained.length} symbol(s)); `
      + 'the section is the code generator placing them, not an introduction of its own',
  };
}

/**
 * A one-screen account of what the subtraction removed, so that a reader can
 * see the baseline doing work rather than take it on trust. This is the number
 * to quote when someone asks whether the detector is just quiet.
 */
export function subtractionReport(result) {
  const { verdicts, byOrigin, classified } = result;
  const total = classified.length;
  const removed = total - verdicts.Unexplained - verdicts.Unresolved;
  const lines = [
    `introduced elements: ${total}`,
    `explained by the toolchain baseline: ${removed}`,
  ];
  for (const [origin, n] of Object.entries(byOrigin)) {
    if (n > 0) lines.push(`  ${origin}: ${n}`);
  }
  lines.push(`Unexplained: ${verdicts.Unexplained}`);
  lines.push(`Unresolved: ${verdicts.Unresolved}`);
  return lines.join('\n');
}
