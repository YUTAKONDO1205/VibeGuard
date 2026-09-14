#!/usr/bin/env node
// bench-score — score a tool's SARIF against this benchmark's label set.
//
// WHY SARIF AND NOT THIS REPOSITORY'S OWN FINDING SHAPE
//
// A benchmark that reads only the shape its author's tool emits is a benchmark
// only its author's tool can enter. SARIF 2.1.0 is what the other candidates
// already produce, so the intake is SARIF and the repository's own format is not
// accepted at all — not even as a convenience. The moment a native path exists it
// becomes the tested one, and the SARIF path rots behind it.
//
// ★ THE DENOMINATOR IS THE LABELS THIS RUN ACTUALLY COVERED.
//
// The corpus is ~1700 repositories and the label set is five. A finding on an
// unlabelled location is not a false positive: nobody has decided what it is. If
// such findings were folded into the numbers they would look like errors, and a
// tool that reports more would score worse for reasons that were never measured.
//
// So findings partition into FOUR disjoint buckets, and all four are printed:
//
//   matched      the finding is within the line window of a labelled site
//   unscored     the rule maps to a family, but no label covers that location
//   unmapped     the rule id maps to no family in the family map
//   unattributed the finding could not be attributed to a manifest entry at all
//
// `unscored` is the one that has to stay visible. Silently folding it into zero
// is the exact failure this file is built to refuse, and the test suite asserts
// the count is non-zero on a fixture that produces one.
//
// ★ AND THE LABEL SIDE PARTITIONS TOO — COVERED vs NOT COVERED.
//
// This was the second silent pass, and it was worse than the first. The scorer
// used to take the denominator as EVERY label in the file, whatever the run had
// actually scanned. `--repository` names ONE repository, so scoring a run over
// one repository reported the other four labelled repositories as `missed` and
// exited 0 — and a tool that scanned nothing at all produced a full set of
// misses and a clean exit. "The tool did not find it" and "the tool was never
// pointed at it" are different sentences and the file printed the first for
// both.
//
// So a label is scored only when the run COVERED its repository, coverage is
// what the run demonstrably reported on (`versionControlProvenance`) plus what
// the caller declared (`--repository`, repeatable), and labels outside that set
// are published in their own NOT COVERED count — never as misses. A run that
// covered no labelled repository is refused outright.
//
// ★ WHY NO RATE IS PRINTED WHEN THE LABELS SAY SO
//
// The label set carries `rateWithheld`. When it is set, this script prints
// integer counts and refuses to divide. That is inherited from the labelling
// pipeline, not invented here: the verdicts are an AI-prepared draft that no
// human has reviewed, and a precision figure over unreviewed verdicts measures
// the drafter. Counts still say something real — how many labelled sites a tool
// reached — so they are published; the ratio is not. Every result file also
// records the CONFIRMATION STATE of the labels it was scored over, because a
// count over an unconfirmed draft and a count over ground truth are not the same
// reading and the counts alone cannot tell them apart.
//
// Usage:
//   node scripts/bench-score.mjs --sarif <file> [--sarif <file> …] \
//        [--labels <file>] [--manifest <file>] [--family-map <file>] \
//        [--repository <id> [--repository <id> …]] [--line-window N] \
//        [--tool NAME --tool-version V] [--out <result.json>]
//
// Exit 0 when a score was produced, 2 on usage, 3 when NOTHING WAS SCORED.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  DEFAULT_LINE_WINDOW,
  EXIT_OK,
  EXIT_USAGE,
  EXIT_VACUOUS,
  MAX_LINE_WINDOW,
  labelProvenanceContradictions,
  manifestDigest,
  normaliseFilePath,
  ratio,
  readJsonOrFail,
  sha256Hex,
  withinWindow,
} from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const BENCH = join(REPO, 'bench', 'ai-code-security-design-smells');

/** A newline, spelled so no shell here-doc or escape rule can eat it. */
const NEWLINE = String.fromCharCode(10);

// ── SARIF intake ────────────────────────────────────────────────────────────

/**
 * Flatten a SARIF log into locatable findings.
 *
 * Tool-neutrality lives or dies here, so this reads only fields the
 * specification requires and every emitter therefore fills:
 *
 *   runs[].tool.driver.name / .version | .semanticVersion
 *   runs[].results[].ruleId
 *   runs[].results[].locations[].physicalLocation.artifactLocation.uri
 *   runs[].results[].locations[].physicalLocation.region.startLine
 *
 * Two shapes are read beyond that and both are optional:
 *
 *   versionControlProvenance — the run's own statement of which repository it
 *     scanned. When absent (Semgrep does not emit it) the caller must say so
 *     with --repository, and if neither is available the finding is reported as
 *     `unattributed` rather than guessed into the only entry in the manifest.
 *     Guessing would be right exactly while the manifest has one entry.
 *
 *   relatedLocations — the other sites a cross-file finding implicates. For this
 *     family they are the point: the claim IS the relationship between sites, and
 *     a tool that reports all of them should not be scored only on whichever one
 *     it happened to put in `locations`. They participate in matching and are
 *     counted separately so a reader can see that they did.
 *
 * A result with no usable location is REFUSED and counted, never dropped: a
 * silently discarded finding is a tool scoring better for emitting something
 * malformed.
 */
export function readSarif(doc, source) {
  const findings = [];
  const refused = [];
  const runs = Array.isArray(doc?.runs) ? doc.runs : null;
  if (runs === null) {
    throw new Error(`${source}: no \`runs\` array — this is not a SARIF log`);
  }

  runs.forEach((run, runIndex) => {
    const driver = run?.tool?.driver ?? {};
    const toolName = typeof driver.name === 'string' ? driver.name : null;
    const toolVersion =
      typeof driver.semanticVersion === 'string'
        ? driver.semanticVersion
        : typeof driver.version === 'string'
          ? driver.version
          : null;

    const vcp = Array.isArray(run?.versionControlProvenance) ? run.versionControlProvenance[0] : null;
    const repositoryUri = typeof vcp?.repositoryUri === 'string' ? vcp.repositoryUri : null;
    const revisionId = typeof vcp?.revisionId === 'string' ? vcp.revisionId : null;

    const results = Array.isArray(run?.results) ? run.results : [];
    results.forEach((r, i) => {
      const ruleId = typeof r?.ruleId === 'string' ? r.ruleId : '';
      if (ruleId === '') {
        refused.push({ source, runIndex, index: i, reason: 'no ruleId — the finding cannot be attributed to a rule' });
        return;
      }
      const primary = locationOf(r?.locations?.[0]);
      if (primary === null) {
        refused.push({ source, runIndex, index: i, ruleId, reason: 'no usable location (artifactLocation.uri + region.startLine)' });
        return;
      }
      const related = (Array.isArray(r?.relatedLocations) ? r.relatedLocations : [])
        .map((l) => locationOf(l))
        .filter((l) => l !== null);

      findings.push({ source, runIndex, ruleId, toolName, toolVersion, repositoryUri, revisionId, primary, related });
    });
  });

  return { findings, refused };
}

function locationOf(loc) {
  const uri = loc?.physicalLocation?.artifactLocation?.uri;
  const line = loc?.physicalLocation?.region?.startLine;
  if (typeof uri !== 'string' || uri === '') return null;
  if (!Number.isInteger(line) || line < 1) return null;
  // SARIF §3.4.1: artifactLocation.uri is a URI reference, so it is percent-
  // encoded. A path with a space in it compares unequal to the label's path
  // until it is decoded, and that mismatch looks exactly like a miss.
  let decoded = uri;
  try {
    decoded = decodeURIComponent(uri);
  } catch {
    // A malformed escape is not a reason to drop the finding; compare raw.
  }
  return { file: normaliseFilePath(decoded), line };
}

// ── Family mapping ──────────────────────────────────────────────────────────

/** ruleId -> family, from a rule-families document. Case-sensitive on purpose. */
export function familyIndex(doc) {
  const index = new Map();
  for (const fam of doc?.families ?? []) {
    for (const rule of fam?.rules ?? []) {
      if (typeof rule?.ruleId === 'string' && typeof fam.family === 'string') {
        index.set(rule.ruleId, fam.family);
      }
    }
  }
  return index;
}

// ── Attribution ─────────────────────────────────────────────────────────────

/** `--repository` is repeatable; a bare string and null are accepted too. */
export function declaredRepositoriesOf(value) {
  if (value === null || value === undefined) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.filter((v) => typeof v === 'string' && v !== '');
}

/**
 * Which manifest entry does this finding belong to?
 *
 * Order: the run's own versionControlProvenance, then the caller's
 * --repository, then nothing. There is deliberately no fourth arm that falls
 * back to "the only entry" — that heuristic is correct while the manifest has
 * one entry and starts silently misattributing the day it has two.
 *
 * ★ And when the caller declared SEVERAL repositories, a finding carrying no
 * provenance of its own is `unattributed` rather than assigned to the first one.
 * The declaration says which repositories were scanned; it does not say which of
 * them any particular finding came from, and picking one would be a guess with a
 * command-line flag in front of it.
 */
export function attribute(finding, byUrl, explicitRepository) {
  if (finding.repositoryUri !== null) {
    const key = String(finding.repositoryUri).replace(/\.git$/, '').replace(/\/+$/, '');
    const hit = byUrl.get(key);
    if (hit !== undefined) return { id: hit, how: 'versionControlProvenance' };
    return { id: null, how: 'versionControlProvenance-unknown', key };
  }
  const declared = declaredRepositoriesOf(explicitRepository);
  if (declared.length === 1) return { id: declared[0], how: '--repository' };
  if (declared.length > 1) return { id: null, how: 'ambiguous-among-declared-repositories' };
  return { id: null, how: 'none' };
}

// ── Scoring ─────────────────────────────────────────────────────────────────

/**
 * Score findings against labels.
 *
 * A label is matched when any of the finding's locations (primary or related)
 * sits in the same file as one of the label's sites and within `window` lines of
 * it. Matching is per LABEL, not per finding: two findings hitting the same
 * label are one matched label and two matched findings, and both numbers are
 * reported because they answer different questions (did the tool find the thing;
 * how noisily).
 *
 * ★ And a label is only SCORED when the run covered its repository. See the
 * header: reporting an unscanned repository's label as a miss is the silent pass
 * this function was rewritten to remove.
 */
export function score(findings, labelSet, manifest, options) {
  const window = options.lineWindow;
  const familyOf = options.familyIndex;
  const declared = declaredRepositoriesOf(options.repositories ?? options.repository ?? null);

  const labels = Array.isArray(labelSet?.labels) ? labelSet.labels : [];
  if (labels.length === 0) {
    return {
      vacuous:
        'the label set is empty. Reporting a score of 0 over an empty denominator is not a ' +
        'result, it is the shape of a result — every tool scores identically and the ranking ' +
        'is an artefact of the emptiness.',
    };
  }

  const byUrl = new Map();
  for (const e of manifest.entries ?? []) {
    byUrl.set(String(e.repositoryUrl).replace(/\.git$/, '').replace(/\/+$/, ''), e.id);
  }

  const labelState = labels.map((l) => ({ label: l, covered: false, matchedBy: [] }));
  const buckets = { matched: [], unscored: [], unmapped: [], unattributed: [] };

  // Pass 1 — bucket every finding, and collect what the run demonstrably
  // reported on. Coverage cannot be decided inside the loop that consumes it.
  const attributedFindings = [];
  const covered = new Set(declared);
  for (const f of findings) {
    const family = familyOf.get(f.ruleId);
    if (family === undefined) {
      buckets.unmapped.push({ ruleId: f.ruleId, file: f.primary.file, line: f.primary.line });
      continue;
    }
    const attributed = attribute(f, byUrl, declared);
    if (attributed.id === null) {
      buckets.unattributed.push({
        ruleId: f.ruleId,
        file: f.primary.file,
        line: f.primary.line,
        how: attributed.how,
        key: attributed.key ?? null,
      });
      continue;
    }
    covered.add(attributed.id);
    attributedFindings.push({ finding: f, family, repository: attributed.id });
  }

  for (const st of labelState) st.covered = covered.has(st.label.repository);

  // Pass 2 — match, over the covered labels. An uncovered label cannot be
  // matched by anything (no finding is attributed to its repository), so the
  // arithmetic is unchanged; the split exists so the counts can be honest.
  for (const { finding: f, family, repository } of attributedFindings) {
    const locations = [f.primary, ...f.related];
    const hit = labelState.find(
      (st) =>
        st.label.repository === repository &&
        st.label.family === family &&
        sitesOf(st.label).some((site) => locations.some((loc) => loc.file === site.file && withinWindow(loc.line, site.line, window))),
    );

    if (hit === undefined) {
      buckets.unscored.push({ repository, family, ruleId: f.ruleId, file: f.primary.file, line: f.primary.line });
    } else {
      hit.matchedBy.push({ ruleId: f.ruleId, file: f.primary.file, line: f.primary.line });
      buckets.matched.push({ repository, family, ruleId: f.ruleId, file: f.primary.file, line: f.primary.line });
    }
  }

  const tp = labelState.filter((s) => s.label.verdict === 'TP');
  const fp = labelState.filter((s) => s.label.verdict === 'FP');
  const tpCovered = tp.filter((s) => s.covered);
  const fpCovered = fp.filter((s) => s.covered);
  const coveredStates = labelState.filter((s) => s.covered);
  const confirmedCovered = coveredStates.filter((s) => s.label.humanConfirmed === true).length;

  return {
    counts: {
      labelsTotal: labels.length,
      labelsTP: tp.length,
      labelsFP: fp.length,
      // ★ THE DENOMINATOR: labels in repositories this run covered.
      labelsCovered: coveredStates.length,
      // Labels in repositories this run did NOT cover. These are NOT misses.
      // Nothing here knows what the tool would have said about them.
      labelsUncovered: labels.length - coveredStates.length,
      labelsTPCovered: tpCovered.length,
      labelsFPCovered: fpCovered.length,
      labelsTPUncovered: tp.length - tpCovered.length,
      labelsFPUncovered: fp.length - fpCovered.length,
      // A covered, labelled TP the tool reported. The recall numerator.
      recovered: tpCovered.filter((s) => s.matchedBy.length > 0).length,
      // A covered, labelled TP the tool did not report anywhere near.
      missed: tpCovered.filter((s) => s.matchedBy.length === 0).length,
      // A covered, labelled FP the tool reported. The rubric already judged this
      // location not to be an instance of the family, so reporting it is an
      // error the benchmark CAN adjudicate — unlike an unlabelled location.
      reportedKnownFalsePositive: fpCovered.filter((s) => s.matchedBy.length > 0).length,
      correctlyAbsentOnKnownFalsePositive: fpCovered.filter((s) => s.matchedBy.length === 0).length,
      findingsTotal: findings.length,
      findingsMatched: buckets.matched.length,
      findingsUnscored: buckets.unscored.length,
      findingsUnmapped: buckets.unmapped.length,
      findingsUnattributed: buckets.unattributed.length,
    },
    coverage: {
      declared: [...declared].sort(),
      repositories: [...covered].sort(),
      labelsConfirmed: confirmedCovered,
      labelsUnconfirmed: coveredStates.length - confirmedCovered,
      groundTruth: [...new Set(coveredStates.map((s) => s.label.groundTruth ?? null))].sort(),
    },
    perLabel: labelState.map((s) => ({
      repository: s.label.repository,
      anchor: s.label.anchor,
      verdict: s.label.verdict,
      covered: s.covered,
      matchedBy: s.matchedBy,
    })),
    buckets,
  };
}

/** Anchor plus sites, de-duplicated: the anchor is usually also a site. */
function sitesOf(label) {
  const out = [];
  const seen = new Set();
  for (const s of [label.anchor, ...(label.sites ?? [])]) {
    if (s === undefined || s === null) continue;
    const key = `${s.file}:${s.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out;
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function flagValue(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i === -1 || argv[i + 1] === undefined ? fallback : argv[i + 1];
}

function flagValues(argv, name) {
  const out = [];
  for (let i = 0; i < argv.length; i += 1) if (argv[i] === name && argv[i + 1] !== undefined) out.push(argv[i + 1]);
  return out;
}

/**
 * A path that can be written into a published file.
 *
 * ★ FOUND BY scripts/check-disclosure-shape.mjs, NOT BY REVIEW. The first
 * version of this script recorded `--family-map` as whatever the caller typed,
 * which for a default invocation is an absolute path — so the very first result
 * file committed under bench/ carried the author's home directory, and with it
 * the account name. The checker flagged it on the first run over the new
 * directory. A result file is a PUBLISHED artefact: submitters send them in, and
 * whatever a submitter's shell expanded lands in the repository.
 *
 * Repo-relative when the file is inside the repository; the basename otherwise,
 * because a path outside it is somebody's machine and carries no information a
 * reader here can use. The sha256 beside it is the identity that actually
 * matters — it survives both reductions.
 */
function portablePath(p) {
  const rel = relative(REPO, p);
  if (rel !== '' && !rel.startsWith('..') && !isAbsolute(rel)) {
    return rel.split(String.fromCharCode(92)).join('/');
  }
  return basename(p);
}

export function main(argv) {
  const fs = { readFileSync };
  const sarifPaths = flagValues(argv, '--sarif');
  if (sarifPaths.length === 0) {
    console.error('bench-score: at least one --sarif <file> is required.');
    return EXIT_USAGE;
  }

  const labelsPath = flagValue(argv, '--labels', join(BENCH, 'labels.json'));
  const manifestPath = flagValue(argv, '--manifest', join(BENCH, 'manifest.json'));
  const familyMapPath = flagValue(argv, '--family-map', join(BENCH, 'rule-families.json'));
  const repositories = flagValues(argv, '--repository');
  const outPath = flagValue(argv, '--out', null);
  const lineWindow = Number(flagValue(argv, '--line-window', String(DEFAULT_LINE_WINDOW)));
  if (!Number.isInteger(lineWindow) || lineWindow < 0) {
    console.error(`bench-score: --line-window must be a non-negative integer, got ${JSON.stringify(flagValue(argv, '--line-window', null))}`);
    return EXIT_USAGE;
  }
  // ★ THE CEILING. Without it the window is a knob that improves your score:
  // widen it far enough and every finding anywhere in a labelled file matches
  // some site in that file, lifting `recovered` and `reportedKnownFalsePositive`
  // together while the result file faithfully records the number that did it.
  if (lineWindow > MAX_LINE_WINDOW) {
    console.error(
      `bench-score: --line-window ${lineWindow} exceeds the maximum of ${MAX_LINE_WINDOW}. The window ` +
        'exists to tolerate two tools choosing different representative lines for the same ' +
        'decision, and those lines sit inside one handler body. A wider window stops matching a ' +
        'SITE and starts matching a FILE, which inflates `recovered` on demand — so a public ' +
        'benchmark cannot offer it as a flag.',
    );
    return EXIT_USAGE;
  }

  let labelSet;
  let manifest;
  let familyDoc;
  let familyMapText;
  let labelsText;
  const findings = [];
  const refused = [];
  try {
    labelsText = readFileSync(labelsPath, 'utf8');
    labelSet = readJsonOrFail(fs, labelsPath, 'label set');
    manifest = readJsonOrFail(fs, manifestPath, 'manifest');
    familyMapText = readFileSync(familyMapPath, 'utf8');
    familyDoc = JSON.parse(familyMapText);
    for (const p of sarifPaths) {
      const parsed = readSarif(readJsonOrFail(fs, p, 'SARIF log'), p);
      findings.push(...parsed.findings);
      refused.push(...parsed.refused);
    }
  } catch (err) {
    console.error(`bench-score: ${err.message}`);
    return EXIT_USAGE;
  }

  // ★ A LABEL SET THAT CONTRADICTS ITSELF IS NOT SCORED. The published rows once
  // carried `groundTruth: "human-review"` beside `humanConfirmed: false`: the
  // field naming who decided the truth disagreed with the field saying whether
  // anybody had. Counts over such a set are readable as either, so the run stops
  // rather than publishing a number whose provenance is a coin flip.
  const contradictions = labelProvenanceContradictions(labelSet);
  if (contradictions.length > 0) {
    console.error(
      [
        `bench-score: ${labelsPath} carries ${contradictions.length} label row(s) whose declared ` +
          'provenance contradicts their confirmation state:',
        ...contradictions.map((c) => `  ${c}`),
        'Refusing to score. A benchmark whose value IS its labels cannot publish a count over ' +
          'rows that disagree with themselves about whether a human ever read them.',
      ].join(NEWLINE),
    );
    return EXIT_USAGE;
  }

  const index = familyIndex(familyDoc);
  if (index.size === 0) {
    console.error(
      `bench-score: the family map ${familyMapPath} maps no rule ids at all. Every finding would ` +
        'land in UNMAPPED and the score would be a statement about the map, not the tool.',
    );
    return EXIT_VACUOUS;
  }

  // ★ ARM 3 OF THE `missed` TRAP: a --repository that names nothing. It used to
  // be scored — every finding landed under an id no label carries, every label
  // was reported as a MISS, and the run exited 0. A typo in a submitted id
  // looked exactly like a tool that detects nothing.
  const manifestIds = new Set((manifest.entries ?? []).map((e) => e.id));
  const unknownRepositories = repositories.filter((r) => !manifestIds.has(r));
  if (unknownRepositories.length > 0) {
    console.error(
      `bench-score: NOTHING WAS SCORED — --repository named ${unknownRepositories.length} id(s) the ` +
        `manifest does not carry: ${unknownRepositories.join(', ')}. The manifest has ` +
        `${manifestIds.size} entry(ies). Scoring under an id no label can ever match would report ` +
        'every labelled site as a MISS, which is a statement about the typed id and would be read ' +
        'as a statement about the tool.',
    );
    return EXIT_VACUOUS;
  }

  const result = score(findings, labelSet, manifest, { lineWindow, familyIndex: index, repositories });
  if (result.vacuous !== undefined) {
    console.error(`bench-score: NOTHING WAS SCORED — ${result.vacuous}`);
    return EXIT_VACUOUS;
  }

  const c = result.counts;

  // ★ THE `missed` TRAP, found by running the Semgrep-shaped fixture against the
  // benchmark's own family map. Every finding landed in UNMAPPED, and the report
  // still said `missed: 1` — which reads as "the tool failed to detect the
  // labelled site" when what actually happened is that no rule id in the run was
  // mapped to the family, so the output never entered the comparison at all.
  // Both sentences are consistent with `recovered: 0`, and only one of them is
  // about the tool.
  //
  // The trap has FIVE arms and for a long time only two were closed. They are
  // separate branches with separate messages, and the suite exercises each on
  // its own, because one passing arm standing in for the others is exactly how
  // this class of defect survives a green test run.
  if (c.findingsTotal === 0) {
    console.error(
      'bench-score: NOTHING WAS SCORED — the SARIF log(s) carry no results at all. A scan that ' +
        'ran and found nothing is byte-identical, from here, to a scan that never ran, so this ' +
        'cannot be published as "missed everything". Re-run the tool and confirm it produced ' +
        'output, or score a log that has results in it.',
    );
    return EXIT_VACUOUS;
  }
  if (c.findingsMatched === 0 && c.findingsUnscored === 0 && c.findingsUnmapped > 0) {
    console.error(
      `bench-score: NOTHING WAS SCORED — all ${c.findingsUnmapped} finding(s) are UNMAPPED: not ` +
        "one rule id in this run maps to a family in the family map, so the tool's output never " +
        'entered the comparison. Publishing the label-side counts here would print "missed" for ' +
        'every labelled site, which is a statement about the MAP and would be read as a statement ' +
        "about the tool. Supply --family-map naming this tool's rule ids.",
    );
    return EXIT_VACUOUS;
  }
  if (c.findingsMatched === 0 && c.findingsUnscored === 0 && c.findingsUnattributed > 0) {
    console.error(
      `bench-score: NOTHING WAS SCORED — all ${c.findingsUnattributed} mapped finding(s) are ` +
        'UNATTRIBUTED: no run carried a versionControlProvenance this manifest recognises, and no ' +
        'single --repository was available to stand in, so not one finding could be tied to a ' +
        'manifest entry. The label side would print "missed" for every site, which is a statement ' +
        'about the ATTRIBUTION and would be read as a statement about the tool. Pass --repository ' +
        '<id>, or emit versionControlProvenance whose repositoryUri matches the manifest.',
    );
    return EXIT_VACUOUS;
  }
  if (c.labelsCovered === 0) {
    console.error(
      `bench-score: NOTHING WAS SCORED — this run covered ${result.coverage.repositories.length} ` +
        `repository(ies) (${result.coverage.repositories.join(', ') || 'none'}) and not one of them ` +
        `carries a label. All ${c.labelsTotal} labelled row(s) lie outside this run's coverage, so ` +
        'there is no denominator. Point the tool at a labelled entry and declare it with ' +
        '--repository, or emit versionControlProvenance.',
    );
    return EXIT_VACUOUS;
  }

  const tool = flagValue(argv, '--tool', findings.find((f) => f.toolName !== null)?.toolName ?? null);
  const toolVersion = flagValue(argv, '--tool-version', findings.find((f) => f.toolVersion !== null)?.toolVersion ?? null);

  const record = {
    schema: 'bench/result@1',
    benchmark: labelSet.benchmark ?? null,
    tool,
    toolVersion,
    date: new Date().toISOString().slice(0, 10),
    manifestDigest: manifestDigest(manifest),
    rubricVersion: labelSet.rubricVersion ?? null,
    familyMap: { path: portablePath(familyMapPath), sha256: sha256Hex(familyMapText) },
    // ★ WHICH LABELS. --labels is a caller-supplied path, so without this a row
    // scored against a label file someone edited is published beside a row scored
    // against this repository's, and the table cannot tell them apart. The
    // manifest and the family map already travel with their digests; the labels
    // are the one input a score is ACTUALLY about, and they were the one input
    // travelling with neither a path nor a digest.
    labelSet: { path: portablePath(labelsPath), sha256: sha256Hex(labelsText) },
    lineWindow,
    lineWindowMax: MAX_LINE_WINDOW,
    rateWithheld: labelSet.rateWithheld ?? null,
    // ★ WHAT THE ROW WAS SCORED OVER. A count over an AI-prepared draft and a
    // count over confirmed ground truth are different readings, and the counts
    // alone cannot tell them apart — so the confirmation state travels with the
    // row into the leaderboard instead of living only in the label file, where
    // nobody reading a table will go and look for it.
    labelProvenance: {
      scope: 'the labels this run covered',
      confirmed: result.coverage.labelsConfirmed,
      unconfirmed: result.coverage.labelsUnconfirmed,
      total: c.labelsCovered,
      groundTruth: result.coverage.groundTruth,
    },
    coverage: {
      declaredWithRepositoryFlag: result.coverage.declared,
      repositories: result.coverage.repositories,
      manifestEntries: [...manifestIds].sort(),
    },
    counts: c,
    // Integer pairs, never a float. Present even when rateWithheld is set,
    // because {num, den} is the counts restated — it is the DIVISION that is
    // withheld, and a reader who may not divide can still read both halves.
    recallPair: ratio(c.recovered, c.labelsTPCovered),
    refusedSarifResults: refused.length,
    perLabel: result.perLabel,
  };

  console.log(`tool:              ${tool ?? '(not stated in the SARIF and not passed with --tool)'}`);
  console.log(`toolVersion:       ${toolVersion ?? '(unstated)'}`);
  console.log(`manifestDigest:    ${record.manifestDigest}`);
  console.log(`lineWindow:        ${lineWindow}  (maximum ${MAX_LINE_WINDOW})`);
  console.log('');
  console.log(`repositories covered: ${result.coverage.repositories.join(', ')}`);
  console.log(`labels:            ${c.labelsTotal}  (TP ${c.labelsTP} / FP ${c.labelsFP})`);
  console.log(`  COVERED:         ${c.labelsCovered}  (TP ${c.labelsTPCovered} / FP ${c.labelsFPCovered})  — the denominator`);
  console.log(`  NOT COVERED:     ${c.labelsUncovered}  (TP ${c.labelsTPUncovered} / FP ${c.labelsFPUncovered})  — not scanned by this run; NOT misses`);
  console.log(`  confirmed:       ${record.labelProvenance.confirmed} of ${record.labelProvenance.total} covered label(s) confirmed by a human`);
  console.log('');
  console.log(`recovered:         ${c.recovered} of ${c.labelsTPCovered} COVERED labelled true positives`);
  console.log(`missed:            ${c.missed}   (covered, labelled TP the run did not report)`);
  console.log(`known-FP reported: ${c.reportedKnownFalsePositive} of ${c.labelsFPCovered} covered`);
  console.log('');
  console.log(`findings:          ${c.findingsTotal}`);
  console.log(`  matched:         ${c.findingsMatched}`);
  console.log(`  UNSCORED:        ${c.findingsUnscored}   (family maps, no label covers the location — NOT an error)`);
  console.log(`  UNMAPPED:        ${c.findingsUnmapped}   (rule id maps to no family — supply --family-map)`);
  console.log(`  unattributed:    ${c.findingsUnattributed}   (no versionControlProvenance and no usable --repository)`);
  console.log(`  refused:         ${refused.length}   (SARIF results with no ruleId or no usable location)`);
  if (record.labelProvenance.unconfirmed > 0) {
    console.log('');
    console.log(
      `LABELS UNCONFIRMED. ${record.labelProvenance.unconfirmed} of ${record.labelProvenance.total} covered ` +
        'label(s) are an AI-prepared draft that no human has confirmed. Every count above is a ' +
        'reading against that draft, not against ground truth.',
    );
  }
  if (record.rateWithheld !== null) {
    console.log('');
    console.log('RATE WITHHELD. Counts only; no precision or recall figure is printed.');
    console.log(record.rateWithheld);
  }

  if (outPath !== null) {
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, `${JSON.stringify(record, null, 2)}${NEWLINE}`, 'utf8');
    console.log(`${NEWLINE}wrote ${outPath}`);
  }
  return EXIT_OK;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
