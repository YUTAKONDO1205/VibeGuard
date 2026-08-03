// Semgrep `--json` report -> ExternalFinding[].
//
// ★★ THE FIELD INTERPRETATION IS NOT A NEW ONE
//
// `scripts/sec-transfer-semgrep.mjs` has been reading this format since the
// transfer experiment, and its three lines of extraction are the interpretation
// of record:
//
//     const f = rel(r.path ?? r.location?.path ?? '');
//     const line = Number(r.start?.line ?? r.start ?? 0);
//     const cid = String(r.check_id ?? '');
//
// A second parser that read `r.extra.lines` for the location, or took
// `r.end.line` as the anchor, or fell back to a different default, would give
// this project two different answers to "what did Semgrep say" — and the first
// person to notice would be a reviewer holding a paper table and a CLI output
// that disagree. So the fallback chain above is reproduced exactly, and
// `parser-parity.test.ts` runs both over the same 20 recorded results and asserts
// agreement on (check_id, path, line) for every one of them. That test also
// asserts those three lines still appear verbatim in the script, so an edit there
// breaks this package's build rather than silently forking the answer.
//
// The one place the two DO differ is the path base, and it is deliberate,
// explained on `AdapterOptions.rootDir`, and covered by its own test: the script
// reduces every path against `process.cwd()` because it only ever reads reports
// it generated itself in the repo root; this package reads reports the user
// generated somewhere unknown.
//
// ★ WHAT IS READ FROM `extra.metadata`, AND WHAT IS POINTEDLY NOT
//
// Read: `cwe` (carried, never used as a join key — see weakness-class.ts for the
// measurement that settled that), and `confidence`, which Semgrep's rule authors
// populate with LOW/MEDIUM/HIGH and which is the only confidence signal in the
// format.
//
// Not read: `impact`, `likelihood`, `subcategory`, `technology`, `references`,
// `source`, `shortlink`, `license`. Each is real and each would be a field this
// package promises to keep meaning something. `Finding` has nowhere to put them
// that a consumer reads, so carrying them would be storage without a reader.
//
// Not read, specifically: `extra.fix`. Semgrep ships autofix text and it is
// tempting to surface as a remediation. It is refused because
// `Finding.remediation` is rendered by the CLI as VibeGuard's advice, in
// VibeGuard's voice, and a fix string from a tool this process never ran would be
// presented as this project's recommendation.
//
// ★ CORRECTED 2026-08-03. This comment used to say the fixture's `extra.fix`
// values are the literal string "requires login" for several rules, and called
// that "the concrete reason, not a hypothetical one". That was FALSE, and the
// assertion beside it (`expect(FIXTURE_TEXT).toContain('"fix"')`) never checked
// it, so it stayed green while being wrong. Measured over all 20 results:
//   extra.fix   === "requires login"  →  0 / 20
//   extra.lines === "requires login"  → 20 / 20
// The redaction is real but it lands on `lines` and `fingerprint`, not on `fix`.
// The three non-null `extra.fix` values in the recording are genuine autofix
// text ("requests.get(..., verify=True)", "False", "crypto/rand"), which is the
// better argument anyway: they ARE usable advice, and printing them in
// VibeGuard's voice is precisely the misattribution this refuses.
//
// (Worth keeping: because `extra.lines` is redacted in all 20, the fixture
// contains no line of the scanned source at all.)

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { normalizeReportPath } from './location.js';
import type { AdapterOptions, ExternalFinding, ExternalReport, RefusedResult, ToolProvenance } from './types.js';
import { ExternalReportError } from './types.js';
import { classifySemgrepCheckId } from './weakness-class.js';

/**
 * Semgrep severity -> VibeGuard severity.
 *
 * ★ THE OBSERVED VALUE SET IS EXACTLY {ERROR, WARNING, INFO}, measured across
 * every recorded Semgrep artifact in this repository:
 *
 *   paper_data/semgrep_vulnerable.json   Semgrep 1.165.0, 20 results   ERROR, WARNING, INFO
 *   paper_data/race_semgrep.json         Semgrep 1.165.0, 20 results   ERROR, WARNING, INFO
 *
 * ★ WHY `ERROR` IS NOT `critical`. Semgrep has three levels and VibeGuard has
 * five; the mapping has to lose or invent information somewhere. Mapping ERROR to
 * `critical` would put every Semgrep ERROR above every VibeGuard `high` in the
 * sorted report — i.e. the tool this process did not run would out-rank the tool
 * it did, systematically, on a severity scale it never used. Mapping to `high`
 * keeps the two comparable and leaves `critical` meaning what it means elsewhere
 * in this codebase: a VibeGuard rule decided it. `rawSeverity` carries the
 * original either way, so nothing is lost, only un-promoted.
 */
const SEMGREP_SEVERITY_TO_VIBEGUARD: Record<string, Severity> = {
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
};

/**
 * Where an unrecognised severity string lands.
 *
 * Semgrep has added levels before (`EXPERIMENT`, `INVENTORY` appear in some
 * newer outputs) and will again. A future value must not crash the parse and must
 * not be silently mapped to the bottom band, which would hide it. `medium` is the
 * neutral middle and `rawSeverity` preserves the unknown string, so a reader sees
 * "medium (raw: EXPERIMENT)" and can judge the mapping themselves.
 */
const UNKNOWN_SEVERITY: Severity = 'medium';

/** Semgrep rule metadata confidence -> VibeGuard confidence. Observed set: LOW, MEDIUM, HIGH. */
const SEMGREP_CONFIDENCE_TO_VIBEGUARD: Record<string, Confidence> = {
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

/**
 * Confidence for a finding whose rule declared none.
 *
 * ★ `medium`, NOT `low`, and the direction matters. `metadata.confidence` is a
 * property of the RULE's metadata block, not a statement about this particular
 * match — a rule author who never filled the field has said nothing about how
 * sure Semgrep is. Defaulting to `low` would let a gap in someone else's metadata
 * push a real finding below every confidence filter in this codebase, i.e. a
 * missing YAML key would delete findings. The evidence line records
 * `semgrep.metadata.confidence=<absent>` so an absent value stays distinguishable
 * from a reported MEDIUM.
 */
const UNKNOWN_CONFIDENCE: Confidence = 'medium';

/** Minimal structural view of the Semgrep JSON. Only the fields this adapter reads. */
interface SemgrepResultShape {
  check_id?: unknown;
  path?: unknown;
  location?: { path?: unknown } | null;
  start?: { line?: unknown; col?: unknown } | number | null;
  end?: { line?: unknown; col?: unknown } | null;
  extra?: {
    message?: unknown;
    severity?: unknown;
    metadata?: { cwe?: unknown; confidence?: unknown } | null;
  } | null;
}

/**
 * Parse a Semgrep `--json` report.
 *
 * Takes the report TEXT, not a path. Nothing in this package touches the
 * filesystem: the caller reads the file (it is the caller who was given the path
 * by the user, and the caller who must decide what reading it is allowed to
 * mean), and `reportPath` is carried through for provenance only. That keeps
 * every function here pure and testable, and keeps the "no I/O, no processes, no
 * sockets" claim in types.ts checkable by reading the imports.
 *
 * Throws `ExternalReportError` when the text is not a Semgrep report. It throws
 * rather than returning an empty report because those are the two facts this
 * package exists to keep apart: an empty report is evidence, an unparseable one
 * is not, and a function that returns `{ findings: [] }` for both has already
 * lost the distinction before the merger can protect it.
 */
export function parseSemgrepReport(reportText: string, options: AdapterOptions): ExternalReport {
  const { reportPath, rootDir } = options;

  let root: unknown;
  try {
    root = JSON.parse(reportText);
  } catch (err) {
    throw new ExternalReportError(
      'semgrep',
      reportPath,
      `not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (root === null || typeof root !== 'object' || Array.isArray(root)) {
    throw new ExternalReportError('semgrep', reportPath, 'top level is not a JSON object');
  }
  const doc = root as Record<string, unknown>;

  // `results` is the one key whose absence means "this is not a Semgrep report".
  // An EMPTY results array is fine and meaningful — it is a clean scan — so the
  // test is on the key's presence and type, never on its length.
  const rawResults = doc['results'];
  if (!Array.isArray(rawResults)) {
    throw new ExternalReportError(
      'semgrep',
      reportPath,
      'no "results" array — this does not look like `semgrep --json` output '
        + '(a SARIF file from `semgrep --sarif` needs the CodeQL/SARIF adapter instead)',
    );
  }

  const provenance: ToolProvenance = {
    tool: 'semgrep',
    versionFromReport: typeof doc['version'] === 'string' ? doc['version'] : null,
    reportPath,
    obtainedBy: 'user-supplied-report',
  };

  const findings: ExternalFinding[] = [];
  const refused: RefusedResult[] = [];
  // Deterministic disambiguation for two results that normalise to the same
  // finding id. Report order is the tiebreak, so the same bytes always produce
  // the same ids — a baseline diff over two runs of the same report must be empty.
  const idCounts = new Map<string, number>();

  for (let index = 0; index < rawResults.length; index += 1) {
    const raw = rawResults[index] as SemgrepResultShape | null;
    if (raw === null || typeof raw !== 'object') {
      refused.push({ index, toolRuleId: '', reason: 'result is not an object' });
      continue;
    }

    const checkId = typeof raw.check_id === 'string' ? raw.check_id : '';
    if (checkId === '') {
      refused.push({ index, toolRuleId: '', reason: 'no check_id — the finding cannot be attributed to a rule' });
      continue;
    }

    // The fallback chain, verbatim from sec-transfer-semgrep.mjs.
    const rawPath = typeof raw.path === 'string' ? raw.path : typeof raw.location?.path === 'string' ? raw.location.path : '';
    const startLine = readLine(raw.start);

    // ★ A RESULT WITH NO LINE IS REFUSED, NOT PLACED AT LINE 1.
    // sec-transfer-semgrep.mjs defaults this to 0, which is safe there because
    // it only ever compares the number to an expected payload line and 0 never
    // matches. Here the number is a CLUSTER KEY: every finding at line 0 in the
    // same file would merge into one, and every finding at line 1 would collide
    // with whatever really is on line 1. A finding that cannot be located cannot
    // be corroborated or contradicted, so it is counted in `refused` — visible,
    // attributable, and out of the merge.
    if (startLine === null || startLine < 1) {
      refused.push({ index, toolRuleId: checkId, reason: 'no usable start.line — the finding cannot be located, so it is not merged' });
      continue;
    }
    if (rawPath === '') {
      refused.push({ index, toolRuleId: checkId, reason: 'no path — the finding cannot be located, so it is not merged' });
      continue;
    }

    const filePath = normalizeReportPath(rawPath, rootDir);
    const extra = raw.extra ?? null;
    const rawSeverity = typeof extra?.severity === 'string' ? extra.severity : null;
    const rawConfidence = typeof extra?.metadata?.confidence === 'string' ? extra.metadata.confidence : null;
    const message = typeof extra?.message === 'string' ? extra.message : '';
    const cweIds = readCwes(extra?.metadata?.cwe);
    const weaknessClass = classifySemgrepCheckId(checkId);

    const ruleId = `semgrep:${checkId}`;
    const idKey = `${filePath}:${startLine}:${ruleId}`;
    const seen = idCounts.get(idKey) ?? 0;
    idCounts.set(idKey, seen + 1);

    findings.push({
      findingId: seen === 0 ? idKey : `${idKey}#${seen + 1}`,
      // ★ NAMESPACED RULE ID. `Finding.ruleId` drives suppression, `--fail-on`
      // and every group-by in the CLI. An un-namespaced `check_id` would sit in
      // the same id space as `VG-INJ-001`, so a `vibeguard:disable-file` pragma
      // naming a rule could silence an external tool's finding — a suppression
      // channel nobody declared. The `semgrep:` prefix keeps the spaces disjoint.
      ruleId,
      title: shortTitle(checkId),
      description: message,
      severity: rawSeverity !== null ? SEMGREP_SEVERITY_TO_VIBEGUARD[rawSeverity] ?? UNKNOWN_SEVERITY : UNKNOWN_SEVERITY,
      confidence: rawConfidence !== null ? SEMGREP_CONFIDENCE_TO_VIBEGUARD[rawConfidence] ?? UNKNOWN_CONFIDENCE : UNKNOWN_CONFIDENCE,
      // The category is the SOURCE, not the weakness. A reader filtering
      // `category === 'external-semgrep'` is asking "what did the other tool
      // say", which is a question this package can answer; a reader filtering on
      // a weakness taxonomy should use `weaknessClass`, which is honest about
      // being null more than half the time.
      category: 'external-semgrep',
      filePath,
      startLine,
      endLine: readLine(raw.end) ?? undefined,
      startColumn: readCol(raw.start),
      endColumn: readCol(raw.end),
      evidence: [
        `semgrep.check_id=${checkId}`,
        `semgrep.severity=${rawSeverity ?? '<absent>'}`,
        `semgrep.metadata.confidence=${rawConfidence ?? '<absent>'}`,
        ...(cweIds.length > 0 ? [`semgrep.metadata.cwe=${cweIds.join(',')}`] : []),
      ],
      sourceEngine: 'semgrep',
      provenance,
      weaknessClass,
      toolRuleId: checkId,
      rawSeverity,
      cweIds,
    });
  }

  return {
    tool: 'semgrep',
    provenance,
    findings,
    refused,
    // Semgrep's own `errors[]` — a scan that failed to parse a file saw less than
    // the whole input. Surfaced because a merger that reads that scan's silence
    // as coverage is wrong in the direction that flatters the result, which is
    // exactly the artifact sec-transfer-semgrep.mjs's assertion A4 exists to catch.
    toolReportedErrors: readToolErrors(doc['errors']),
    scannedPaths: readScannedPaths(doc['paths'], rootDir),
  };
}

/**
 * `r.start?.line ?? r.start ?? 0` from the source script, with the `0` sentinel
 * replaced by `null` so the caller can distinguish "absent" from "line 0".
 *
 * The `?? r.start` arm looks odd and is kept because the source script has it:
 * it tolerates a `start` that is a bare number rather than `{line, col}`. No
 * recorded artifact in this repository contains that shape, so it is carried for
 * parity rather than for a case anyone has seen.
 */
function readLine(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  if (value !== null && typeof value === 'object') {
    const line = (value as { line?: unknown }).line;
    if (typeof line === 'number' && Number.isFinite(line)) return Math.trunc(line);
  }
  return null;
}

function readCol(value: unknown): number | undefined {
  if (value !== null && typeof value === 'object') {
    const col = (value as { col?: unknown }).col;
    if (typeof col === 'number' && Number.isFinite(col)) return Math.trunc(col);
  }
  return undefined;
}

/**
 * `["CWE-295: Improper Certificate Validation"]` -> `["CWE-295"]`.
 *
 * The prose after the colon is dropped: it is the CWE title, it is long, and it
 * is not stable across CWE releases, so keeping it would make two reports of the
 * same weakness compare unequal on a string nobody meant to compare. Anything not
 * matching `CWE-<digits>` is dropped rather than passed through, because a
 * malformed entry that reaches a consumer looks like a CWE id and is not one.
 */
function readCwes(value: unknown): string[] {
  const items = Array.isArray(value) ? value : value === undefined || value === null ? [] : [value];
  const out: string[] = [];
  for (const item of items) {
    if (typeof item !== 'string') continue;
    const match = /^CWE-([0-9]{1,7})/.exec(item.trim());
    if (match) out.push(`CWE-${match[1]}`);
  }
  return [...new Set(out)].sort();
}

/** Semgrep's `errors[]`, flattened to printable strings. Shape varies by version, so this is tolerant. */
function readToolErrors(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((e) => {
    if (typeof e === 'string') return e;
    if (e !== null && typeof e === 'object') {
      const obj = e as Record<string, unknown>;
      const message = typeof obj['message'] === 'string' ? obj['message'] : JSON.stringify(e);
      const type = typeof obj['type'] === 'string' ? obj['type'] : null;
      return type === null ? message : `${type}: ${message}`;
    }
    return String(e);
  });
}

/**
 * `paths.scanned` — the files Semgrep says it opened.
 *
 * Worth carrying for the reason `sast-baseline-eval.mjs` spells out at length:
 * "Semgrep-only" and "VibeGuard-only" are only meaningful over files the other
 * tool actually analysed, and using a file EXTENSION as a proxy counts files the
 * tool skipped or failed to parse as misses. This package does not yet gate on
 * the set — the merger's agreement labels are per-finding, not per-file — but the
 * data is preserved so the gate can be added without a second parse, and so a
 * report with a suspiciously small scanned set is visible.
 */
function readScannedPaths(value: unknown, rootDir?: string): string[] {
  if (value === null || typeof value !== 'object') return [];
  const scanned = (value as { scanned?: unknown }).scanned;
  if (!Array.isArray(scanned)) return [];
  const out = scanned.filter((p): p is string => typeof p === 'string').map((p) => normalizeReportPath(p, rootDir));
  return [...new Set(out)].sort();
}

/**
 * The last dot-segment of a check_id, as a human title.
 *
 * `python.requests.security.disabled-cert-validation.disabled-cert-validation`
 * renders as `disabled-cert-validation`. The full id is never lost — it is on
 * `toolRuleId`, on `ruleId`, and in `evidence` — so this is presentation only,
 * and a lossy presentation is the right call for a field the CLI prints on one
 * line beside a path.
 */
function shortTitle(checkId: string): string {
  const parts = checkId.split('.');
  const last = parts[parts.length - 1];
  return last !== undefined && last !== '' ? last : checkId;
}
