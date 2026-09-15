#!/usr/bin/env node
// bench-build-manifest — turn the private pin/label files into the public
// benchmark's manifest and label set, WITHOUT copying a byte of anybody's code.
//
// WHAT THIS SCRIPT IS FOR
//
// The corpus this benchmark scores against is ~1700 third-party repositories.
// None of it can be redistributed: the licences are unknown (see LICENCE STATUS
// below), the repositories are other people's, and vendoring them would make
// this repository a mirror of code it has no right to mirror. So the published
// artefact is a MANIFEST — a URL and a pinned commit per entry — plus a fetch
// script. Nothing under bench/ is third-party source, and the test suite asserts
// that rather than trusting it.
//
// The inputs live under the gitignored evaluation directory and are NOT present
// in a clean clone or in CI. That is why this is a build step whose OUTPUT is
// committed, not a library the scorer calls at run time.
//
// LICENCE STATUS — READ BEFORE ASSUMING A FIELD IS MISSING BY ACCIDENT
//
// Not one of the available inputs carries a licence. The pin files carry
// {sha, remote, committed, branch}; the corpus manifests carry
// {full_name, clone_url, language, stars, kb, dir}. There is no licence field to
// transcribe, and inventing one — or defaulting it to "unknown" in a way that
// reads like "probably fine" — would be the worst option on offer, because the
// next person to publish a derived corpus would inherit a licence column that
// was never sourced from anything.
//
// So every entry carries `licence.status: "unresolved"` with the reason, the
// manifest carries the integer ratio of resolved entries, and the FETCH SCRIPT
// refuses to clone an unresolved entry unless the caller passes an explicit
// flag. The refusal is the honest form of the gap: the data is missing, the
// missing-ness is machine-readable, and acting on it takes a deliberate word.
//
// Usage:
//   node scripts/bench-build-manifest.mjs                      # build in place
//   node scripts/bench-build-manifest.mjs --check              # verify, write nothing
//   node scripts/bench-build-manifest.mjs --from D --out D2    # for the tests
//
// Exits 0 on success, 2 on a usage/input error, 1 when --check finds drift.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  EXIT_FINDINGS,
  EXIT_OK,
  EXIT_USAGE,
  labelProvenanceContradictions,
  normaliseFilePath,
  ratio,
  readJsonOrFail,
} from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_IN = join(REPO, 'paper_data');
const DEFAULT_OUT = join(REPO, 'bench', 'ai-code-security-design-smells');

const fs = { readFileSync };

/** A newline, spelled so no shell here-doc or escape rule can eat it. */
const NEWLINE = String.fromCharCode(10);

/** The one rule family this benchmark's v0 label set covers. */
export const FAMILY = 'inline-authorization';

const LICENCE_UNRESOLVED = Object.freeze({
  spdx: null,
  status: 'unresolved',
  reason:
    'No licence field exists in any input available to the builder (neither the upstream pin ' +
    'records nor the corpus manifests carry one). Resolving it requires a network call to the ' +
    'forge, which this build step does not make. See bench-fetch.mjs --allow-unresolved-licence.',
});

/**
 * The join key. It is the corpus directory name, not the repository's
 * `owner/name`, because that is the key the label rows were written against and
 * a benchmark whose labels and manifest disagree about what a repository is
 * called scores nothing while looking healthy.
 */
const idOf = (label) => label.repo;

/**
 * Build the manifest and label set.
 *
 * Pure with respect to the filesystem apart from the three reads, so the tests
 * can drive it over a synthetic input directory and get the same code path CI
 * would get — not a mock of it.
 */
export function build(inputDir) {
  const labelsPath = join(inputDir, 'smell010_labels.json');
  const pinsPath = join(inputDir, 'corpus-pins-2026-08-04', 'corpus1k_vibe-upstream-pins.json');
  const manifestPath = join(inputDir, 'corpus1k_vibe_manifest.json');

  const labelDoc = readJsonOrFail(fs, labelsPath, 'label source');
  const pinDoc = readJsonOrFail(fs, pinsPath, 'upstream pins');
  const corpusDoc = readJsonOrFail(fs, manifestPath, 'corpus manifest');

  const labelRows = Array.isArray(labelDoc.labels) ? labelDoc.labels : null;
  if (labelRows === null || labelRows.length === 0) {
    throw new Error(
      `label source ${labelsPath} carries no \`labels\` array. Building a benchmark whose ` +
        'denominator is empty is the defect this whole lane exists to refuse.',
    );
  }
  if (typeof labelDoc.rubricVersion !== 'string' || labelDoc.rubricVersion === '') {
    throw new Error(
      `label source ${labelsPath} carries no rubricVersion. A verdict without the version of ` +
        'the rubric it was made under cannot be re-derived, so it is not a label.',
    );
  }

  const pins = pinDoc.pins ?? {};
  const byDir = new Map((corpusDoc.repos ?? []).map((r) => [r.dir, r]));

  const entries = [];
  const labels = [];
  const missing = [];

  for (const row of labelRows) {
    const id = idOf(row);
    const pin = pins[id];
    const meta = byDir.get(id);
    if (pin === undefined || meta === undefined) {
      missing.push(`${id}: ${pin === undefined ? 'no upstream pin' : ''}${meta === undefined ? ' no corpus metadata' : ''}`);
      continue;
    }

    entries.push({
      id,
      repositoryUrl: String(pin.remote).replace(/\.git$/, ''),
      commit: pin.sha,
      defaultBranch: pin.branch,
      committedAt: pin.committed,
      primaryLanguage: meta.language,
      sizeKb: meta.kb,
      licence: LICENCE_UNRESOLVED,
    });

    const sites = dedupeSites(row._sites ?? []);
    const anchor = anchorOf(row, sites);
    labels.push({
      repository: id,
      family: FAMILY,
      toolRuleIdAtLabelTime: 'VG-SMELL-010',
      verdict: row.verdict,
      anchor,
      sites,
      rubricVersion: labelDoc.rubricVersion,
      // ★ NOT THE CONSTANT 'human-review'. It WAS that constant, and the
      // published label set therefore declared a provenance it did not have:
      // five rows saying a human reviewed them, beside humanConfirmed:false and
      // a labeledBy naming an AI drafter. The provenance is transcribed when the
      // source states one and DERIVED from the one fact the source does carry
      // when it does not — and labelProvenanceContradictions() below refuses the
      // whole build if the two ever disagree, which is the only arm a future
      // source that starts carrying its own groundTruth can trip.
      groundTruth:
        typeof row.groundTruth === 'string'
          ? row.groundTruth
          : row.humanConfirmed === true
            ? 'human-review'
            : 'ai-draft-unconfirmed',
      humanConfirmed: row.humanConfirmed === true,
      labeledBy: row.labeledBy,
      rationale: row.rationale,
    });
  }

  if (missing.length > 0) {
    throw new Error(
      `${missing.length} labelled repository(ies) could not be resolved against the pins/manifest:\n  ` +
        missing.join('\n  ') +
        '\nA manifest that quietly drops the entries it could not resolve publishes a smaller ' +
        'benchmark than the label set claims.',
    );
  }

  const confirmed = labels.filter((l) => l.humanConfirmed).length;

  const manifest = {
    benchmark: 'ai-code-security-design-smells',
    manifestVersion: 'v0',
    generatedBy: 'scripts/bench-build-manifest.mjs',
    redistribution:
      'MANIFEST ONLY. No third-party source code is stored in this repository. Entries are ' +
      'fetched at the pinned commit by scripts/bench-fetch.mjs.',
    provenance: {
      corpus: corpusDoc.corpus ?? pinDoc.corpus ?? null,
      corpusRepositories: (corpusDoc.repos ?? []).length,
      upstreamPinsRecorded: pinDoc.repoCount ?? null,
      entriesPublished: entries.length,
      note:
        'entriesPublished is the LABELLED subset, not the whole corpus. An entry with no label ' +
        'contributes nothing to a score (every finding on it would be UNSCORED), so v0 ships the ' +
        'part the scorer can actually decide. Widening the manifest requires widening the labels.',
    },
    licenceResolved: ratio(entries.filter((e) => e.licence.status === 'resolved').length, entries.length),
    entries: entries.sort((a, b) => (a.id < b.id ? -1 : 1)),
  };

  const labelSet = {
    benchmark: 'ai-code-security-design-smells',
    generatedBy: 'scripts/bench-build-manifest.mjs',
    rubricVersion: labelDoc.rubricVersion,
    rubricDocument: labelDoc.rubric ?? null,
    family: FAMILY,
    humanConfirmed: ratio(confirmed, labels.length),
    rateWithheld:
      confirmed === labels.length
        ? null
        : 'No rate may be computed from this label set. The verdicts are an AI-prepared draft and ' +
          'no human has read the implicated handlers; a precision figure over unreviewed verdicts ' +
          'measures the drafter, not the tool. The scorer therefore emits integer counts only. ' +
          'Flip humanConfirmed at the source, rebuild, and the withholding lifts by itself.',
    labels: labels.sort((a, b) => (a.repository < b.repository ? -1 : 1)),
  };

  // The derivation above cannot produce a contradiction, which is exactly why
  // the check runs anyway: the next edit to this function is the one that can,
  // and a benchmark that declares an unearned provenance is worth less than no
  // benchmark. Same function the scorer refuses on, so the two cannot drift.
  const contradictions = labelProvenanceContradictions(labelSet);
  if (contradictions.length > 0) {
    throw new Error(
      [
        `${contradictions.length} label row(s) declare a provenance they do not have:`,
        ...contradictions.map((c) => `  ${c}`),
        'A row saying a human reviewed it while carrying humanConfirmed:false is the one ' +
          'defect a label set cannot survive, because the labels are the whole artefact.',
      ].join(NEWLINE),
    );
  }

  return { manifest, labelSet };
}

/** One (file, line) per site: the raw rows repeat a line for each matched span. */
function dedupeSites(rawSites) {
  const seen = new Set();
  const out = [];
  for (const s of rawSites) {
    const file = normaliseFilePath(s.filePath ?? s.file ?? '');
    const line = Number(s.startLine ?? s.line);
    if (file === '' || !Number.isInteger(line) || line < 1) continue;
    const key = `${file}:${line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ file, line });
  }
  return out.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));
}

/**
 * The anchor is read from the finding key the verdict was written against, so it
 * is the site a reader of the label would go to first. It falls back to the
 * first site rather than to nothing: a label with no location cannot be matched
 * by anything, which would silently shrink the denominator.
 */
function anchorOf(row, sites) {
  const m = /#([^#]+):(\d+)#/.exec(String(row.findingKey ?? ''));
  if (m !== null) return { file: normaliseFilePath(m[1]), line: Number(m[2]) };
  if (sites.length > 0) return { ...sites[0] };
  throw new Error(`label for ${row.repo} has neither a parseable findingKey nor any site`);
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function flagValue(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i === -1 || argv[i + 1] === undefined ? fallback : argv[i + 1];
}

function main(argv) {
  const check = argv.includes('--check');
  const inputDir = flagValue(argv, '--from', DEFAULT_IN);
  const outDir = flagValue(argv, '--out', DEFAULT_OUT);

  let built;
  try {
    built = build(inputDir);
  } catch (err) {
    console.error(`bench-build-manifest: ${err.message}`);
    console.error(
      '\nThe inputs live in the gitignored evaluation directory and are absent from a clean ' +
        'clone. That is expected: the OUTPUT of this script is committed, the input is not. ' +
        'This is an error rather than a skip so that a run which built nothing can never be ' +
        'mistaken for a run which built the same thing as last time.',
    );
    return EXIT_USAGE;
  }

  const targets = [
    ['manifest.json', built.manifest],
    ['labels.json', built.labelSet],
  ];

  if (check) {
    const drift = [];
    for (const [name, value] of targets) {
      const path = join(outDir, name);
      if (!existsSync(path)) {
        drift.push(`${name}: does not exist`);
        continue;
      }
      const onDisk = readFileSync(path, 'utf8');
      const rebuilt = `${JSON.stringify(value, null, 2)}\n`;
      if (onDisk !== rebuilt) drift.push(`${name}: differs from a fresh build`);
    }
    if (drift.length > 0) {
      for (const d of drift) console.error(`DRIFT  ${d}`);
      console.error('\nRun: node scripts/bench-build-manifest.mjs');
      return EXIT_FINDINGS;
    }
    console.log(`bench-build-manifest --check: ${targets.length} file(s) match a fresh build.`);
    return EXIT_OK;
  }

  mkdirSync(outDir, { recursive: true });
  for (const [name, value] of targets) {
    writeFileSync(join(outDir, name), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    console.log(`wrote ${join(outDir, name)}`);
  }
  console.log(
    `entries=${built.manifest.entries.length} labels=${built.labelSet.labels.length} ` +
      `humanConfirmed=${built.labelSet.humanConfirmed.num}/${built.labelSet.humanConfirmed.den} ` +
      `licenceResolved=${built.manifest.licenceResolved.num}/${built.manifest.licenceResolved.den}`,
  );
  return EXIT_OK;
}

// `pathToFileURL` rather than a hand-built `file://` prefix: on Windows the
// correct spelling is `file:///C:/…` with three slashes, and a two-slash guess
// makes this block never fire — the script would import cleanly and do nothing,
// which is the quietest possible way for a build step to stop building.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
