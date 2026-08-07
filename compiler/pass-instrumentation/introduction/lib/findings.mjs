// Turning verdicts into findings, in the shape interfaces.md §2 fixes.
//
// Only Unexplained elements become findings. Unresolved elements become the
// other thing this component can report -- an incompleteness -- because "we
// could not decide" and "we decided it is wrong" are different claims and
// exit 3 exists precisely so that the first is not filed under the second.
//
// The attribution carried on a finding is a (pass, IR unit) pair whenever one
// was measured. interfaces.md §2 says `where.unit` and `where.pass` are null
// when the finding is not attributable to one, and that null means "not
// applicable", never "not looked at" -- so an element seen only in the object
// file gets nulls and says in its detail that the pass level was not where it
// was found, while an element the pass observer watched appear carries the pass
// that introduced it and the unit it appeared in.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { severityAtLeast } from './policy.mjs';

export const FINDING_META = {
  'VG-INTRO-001': {
    severity: 'high',
    title: 'A symbol appeared that no permitted origin explains',
  },
  'VG-INTRO-002': {
    severity: 'high',
    title: 'A call leaves this object to a target the policy does not approve',
  },
  'VG-INTRO-003': {
    severity: 'critical',
    title: 'A static initialiser appeared that no permitted origin explains',
  },
  'VG-INTRO-004': {
    severity: 'high',
    title: 'An executable section appeared that no permitted origin explains',
  },
};

function whereFor(element, path) {
  const intro = element.firstIntroduction;
  if (intro && intro.pass) {
    return { kind: 'ir', path, unit: intro.unit ?? null, pass: intro.pass };
  }
  return { kind: 'object', path, unit: null, pass: null };
}

function attributionSentence(element) {
  const intro = element.firstIntroduction;
  if (!intro) {
    return 'The pass observer did not watch this compilation, so which pass introduced '
      + 'it was not observed -- that is not the same as no pass having introduced it.';
  }
  if (intro.atEntry) {
    return 'It was already present at the first observation of its IR unit, so the front '
      + `end emitted it rather than a pass (${intro.unit}).`;
  }
  const prev = intro.previousAfterPass
    ? ` The pass that ran immediately before it on that unit was ${intro.previousAfterPass}.`
    : '';
  return `First introduced by ${intro.pass} in ${intro.unit}, at observation ${intro.seq}.${prev}`;
}

function stateSentence(element) {
  const series = element.stateSeries;
  if (!Array.isArray(series) || series.length === 0) return '';
  const states = series.map((s) => s.state).join(' -> ');
  return ` State series across the whole pipeline: ${states}.`;
}

/**
 * Decide, for one Unexplained element, whether a finding is produced.
 *
 * External calls are the one kind with a second gate. Under the default
 * `baseline` mode the baseline is the whole test; under `allowlist` a call the
 * source declared must also be on the approved list, because "the source asked
 * for it" is exactly the claim an operator may want to stop accepting.
 */
export function findingFor(element, { policy, path }) {
  const id = element.finding;
  const meta = FINDING_META[id];
  if (!meta) return null;

  if (element.verdict !== 'Unexplained') {
    if (element.kind !== 'extcall') return null;
    if (policy.externalCalls.mode !== 'allowlist') return null;
    if (element.origin !== 'source-derived') return null;
    if (policy.externalCalls.approved.includes(element.name)) return null;
    return {
      id,
      severity: meta.severity,
      title: meta.title,
      detail: `${element.name}: ${element.detail?.callSites ?? '?'} call site(s) from `
        + `${element.where}. The source declares this call, but the policy runs in `
        + 'allowlist mode and externalCalls.approved does not list it.',
      where: whereFor(element, path),
    };
  }

  if (element.kind === 'extcall' && policy.externalCalls.approved.includes(element.name)) {
    return null;
  }
  if (element.kind === 'section' && policy.sections.approvedExecutable.includes(element.name)) {
    return null;
  }

  const site = element.kind === 'extcall'
    ? `${element.detail?.callSites ?? '?'} call site(s) in ${element.where}`
    : `in ${element.where}`;

  return {
    id,
    severity: meta.severity,
    title: meta.title,
    detail: `${element.name} (${element.kind}, ${site}). ${element.reason}. `
      + `${attributionSentence(element)}${stateSentence(element)}`,
    where: whereFor(element, path),
  };
}

/**
 * @returns {{findings: object[], incomplete: object[]}}
 */
export function buildFindings(classified, { policy, path }) {
  const findings = [];
  const incomplete = [];
  for (const element of classified) {
    if (element.verdict === 'Unresolved') {
      incomplete.push({
        element: `${element.kind}:${element.name}`,
        rule: element.rule,
        reason: element.reason,
      });
      continue;
    }
    const f = findingFor(element, { policy, path });
    if (f) findings.push(f);
  }
  findings.sort((a, b) => (a.id === b.id ? a.detail.localeCompare(b.detail) : a.id.localeCompare(b.id)));
  return { findings, incomplete };
}

/** Findings at or above the policy's failure threshold. */
export function failing(findings, policy) {
  return findings.filter((f) => severityAtLeast(f.severity, policy.failOn));
}
