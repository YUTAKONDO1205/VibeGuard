// PROV — AI-provenance generation grid: the SCORING half.
//
// ★★ WHAT THIS SCRIPT IS, AND WHY IT DOES NOT GENERATE ANYTHING
//
// The experiment behind #29b asks whether the security properties of generated
// code move with the knobs a user turns: task spec × model × model version ×
// prompt style × temperature. Producing that grid requires model API access.
// There is none on the machine this repository is developed on, and inventing
// the sources locally would produce a grid of MY code labelled with model names
// — a fabricated experimental result, which is worse than no result.
//
// So the grid arrives as INPUT. This script is the half that can be written
// honestly here: it takes a manifest produced elsewhere, refuses it if it is not
// a complete grid, scores every cell with the SHIPPED rules, and writes a result
// file that is byte-identical on re-run. The generator is somebody else's
// program; the contract it must satisfy is the manifest schema below, and this
// script is the enforcement of that contract.
//
// ★ THE DoD IS BYTE-IDENTICAL OUTPUT ON RE-RUN, AND IT COSTS ONE CONVENTION
//
// sec-b1-gen-corpus.mjs and sec-b3-gen-corpus.mjs both record
// `provenance.generatedAt = new Date().toISOString()`, and b3's header calls it
// "the ONE clock read in this script", deliberately excluded when checking two
// runs for byte equality. That works there because their DoD is "the CORPUS
// bytes are reproducible", with the manifest allowed to differ in one field.
//
// This script's DoD is stricter — the OUTPUT FILE itself must be byte-identical
// — so the exemption is not available and the clock is not read at all. The
// `generatedAt` in the output is the manifest's own, echoed: it records when the
// CORPUS was generated, by the generator, which is the timestamp a reader
// actually needs. A scoring run has no interesting time of its own; if you need
// one, the filesystem has it.
//
// Everything else that could vary between runs is pinned:
//   - no Math.random, no Date, no process.hrtime anywhere in the output path;
//   - every directory listing and every map iteration is sorted;
//   - every path is repo-relative with forward slashes, so the JSON does not
//     carry the home directory of whoever ran it;
//   - `JSON.stringify(x, null, 2) + '\n'` written with writeFileSync, which does
//     no line-ending translation on any platform — the file is LF on Windows too.
//
// `--selftest` runs the whole pipeline twice over the recorded sample and
// byte-compares. It is not a unit test of a helper; it re-executes everything
// including the git provenance read, because "byte-identical on re-run" is a
// claim about the program, not about a function inside it.
//
// ★ THE RECORDED SAMPLE IS NOT A RESULT, AND THE JSON SAYS SO
//
// `scripts/fixtures/prov-sample/` holds a hand-written three-cell corpus whose
// only job is to keep this pipe executable end to end from a fresh checkout.
// Its "model" is a placeholder that never existed. Every output carries
// `corpusOrigin`, and when that is `recorded-sample` the output also carries
// `resultStatus: 'not-an-experimental-result'` with the reason spelled out in
// prose inside the file — because a JSON file outlives the terminal session that
// produced it, and the next person to open it will not have read this comment.
// A stderr banner says the same thing at run time.
//
// Usage (from the repository root; packages/rules/dist must be built):
//   node scripts/sec-prov-gen-corpus.mjs --manifest scripts/fixtures/prov-sample/manifest.json
//   node scripts/sec-prov-gen-corpus.mjs --selftest
//
// ZERO TRANSMISSION: reads the filesystem and runs `git`. No network client is
// imported and none is reachable.

import { readFileSync, writeFileSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join, dirname, resolve, relative, extname, sep } from 'node:path';
import { allRules, languageMatches } from '@vibeguard/rules';

const REPO_ROOT = process.cwd();
const RESULTS_DIR = 'security-experiment/_results';
const SAMPLE_MANIFEST = 'scripts/fixtures/prov-sample/manifest.json';
const OUTPUT_SCHEMA_VERSION = 1;
const MANIFEST_SCHEMA_VERSION = 1;

/** Same table the other sec-* scripts use. A file whose extension is absent is a validation error, not a silent skip. */
const LANG_BY_EXT = {
  '.py': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.go': 'go',
  '.java': 'java',
  '.rb': 'ruby',
  '.php': 'php',
  '.cs': 'csharp',
};

const slash = (p) => p.replace(/\\/g, '/');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * A path as it should appear in the output: repo-relative, forward slashes,
 * never absolute.
 *
 * A manifest handed in from outside the repository would otherwise put the
 * operator's home directory into a JSON file that gets committed to a paper
 * repository or pasted into a review. It is also a determinism hazard: two
 * machines scoring the same corpus would produce different bytes for the same
 * measurement.
 */
function repoRelative(abs) {
  const rel = relative(REPO_ROOT, abs);
  if (rel === '' || rel.startsWith('..') || /^[a-zA-Z]:/.test(rel)) return '(outside repository root)';
  return slash(rel);
}

// ---------------------------------------------------------------------------
// THE INPUT CONTRACT
//
// A manifest is accepted only if it is a COMPLETE grid. That is the whole point
// of validating rather than just scoring whatever showed up: an incomplete grid
// scored silently produces a table with holes, and a table with holes reads as a
// measurement. "model B has no findings at temperature 0.7" and "nobody
// generated model B at temperature 0.7" are the same picture in a bar chart and
// opposite claims.
//
// Shape (schemaVersion 1):
//
//   {
//     "schemaVersion": 1,
//     "corpusId": "…",                        // filename-safe; names the output
//     "corpusOrigin": "external-input" | "recorded-sample",
//     "generatedAt": "<ISO-8601 from the GENERATOR>",
//     "generator": { "name": "…", "version": "…" },
//     "grid": {
//       "taskSpecs":     [ { "id", "title", "language" } ],
//       "models":        [ { "id", "vendor", "name" } ],
//       "modelVersions": { "<modelId>": ["…", …] },
//       "promptStyles":  ["…", …],
//       "temperatures":  [0, 0.7],
//       "samplesPerCell": 1
//     },
//     "cells": [ {
//       "cellId": "<derived — see cellIdOf>",
//       "taskSpec", "model", "modelVersion", "promptStyle",
//       "temperature", "sampleIndex",
//       "files": [ { "path": "<relative to the manifest's directory>", "sha256": "…" } ]
//     } ]
//   }
//
// `modelVersion` is its own axis rather than being folded into the model id,
// because "the same model got worse at version N+1" is the question this grid
// exists to be able to ask, and folding it in would make that a comparison
// between two unrelated models.
// ---------------------------------------------------------------------------

/**
 * The canonical id of a grid coordinate.
 *
 * Derived rather than trusted: the manifest carries `cellId` too, and the two
 * are compared. A manifest whose ids have drifted from its coordinates (a
 * hand-edit, a partial regeneration) is one where every join downstream is
 * silently wrong, and that is exactly the failure that survives review.
 *
 * The temperature is formatted through `formatTemperature` so `0`, `0.0` and
 * `0.00` in the input JSON cannot produce three different ids for one cell.
 */
function cellIdOf(cell) {
  return [
    cell.taskSpec,
    cell.model,
    cell.modelVersion,
    cell.promptStyle,
    `t${formatTemperature(cell.temperature)}`,
    `s${cell.sampleIndex}`,
  ].join('__');
}

/** Fixed-precision temperature, so the id and the grouping key never disagree with the JSON literal. */
function formatTemperature(t) {
  return Number(t).toFixed(2);
}

function fail(errors, message) {
  errors.push(message);
}

/**
 * Validate the manifest and resolve every cell's files.
 *
 * Returns `{ errors, missingCells, unexpectedCells, cells }`. Nothing throws:
 * the caller writes the report — errors included — and THEN exits non-zero, so
 * a rejected manifest still leaves a machine-readable record of why.
 */
function validateManifest(manifest, corpusRoot) {
  const errors = [];

  if (manifest.schemaVersion !== MANIFEST_SCHEMA_VERSION) {
    fail(errors, `schemaVersion must be ${MANIFEST_SCHEMA_VERSION}, got ${JSON.stringify(manifest.schemaVersion)}`);
  }
  if (manifest.corpusOrigin !== 'external-input' && manifest.corpusOrigin !== 'recorded-sample') {
    fail(
      errors,
      `corpusOrigin must be 'external-input' or 'recorded-sample', got ${JSON.stringify(manifest.corpusOrigin)}. ` +
        'There is no third kind: either a generator produced this elsewhere, or it is the sample shipped to keep the pipe runnable.',
    );
  }
  if (typeof manifest.corpusId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(manifest.corpusId)) {
    fail(errors, 'corpusId must be a filename-safe string of 1-64 chars ([A-Za-z0-9._-], not starting with punctuation)');
  }
  if (typeof manifest.generatedAt !== 'string' || Number.isNaN(Date.parse(manifest.generatedAt))) {
    fail(errors, 'generatedAt must be an ISO-8601 timestamp recorded by the GENERATOR (this script never reads a clock)');
  }

  const grid = manifest.grid ?? {};
  const taskSpecs = Array.isArray(grid.taskSpecs) ? grid.taskSpecs : [];
  const models = Array.isArray(grid.models) ? grid.models : [];
  const modelVersions = grid.modelVersions && typeof grid.modelVersions === 'object' ? grid.modelVersions : {};
  const promptStyles = Array.isArray(grid.promptStyles) ? grid.promptStyles : [];
  const temperatures = Array.isArray(grid.temperatures) ? grid.temperatures : [];
  const samplesPerCell = grid.samplesPerCell;

  if (taskSpecs.length === 0) fail(errors, 'grid.taskSpecs is empty');
  if (models.length === 0) fail(errors, 'grid.models is empty');
  if (promptStyles.length === 0) fail(errors, 'grid.promptStyles is empty');
  if (temperatures.length === 0) fail(errors, 'grid.temperatures is empty');
  if (!Number.isInteger(samplesPerCell) || samplesPerCell < 1) {
    fail(errors, 'grid.samplesPerCell must be a positive integer');
  }

  const taskSpecIds = new Set();
  for (const t of taskSpecs) {
    if (!t || typeof t.id !== 'string') { fail(errors, 'grid.taskSpecs entry without a string id'); continue; }
    if (taskSpecIds.has(t.id)) fail(errors, `duplicate taskSpec id ${t.id}`);
    taskSpecIds.add(t.id);
    if (typeof t.language !== 'string' || t.language === '') {
      fail(errors, `taskSpec ${t.id} declares no language; the scorer cannot pick rules without one`);
    }
  }
  const modelIds = new Set();
  for (const m of models) {
    if (!m || typeof m.id !== 'string') { fail(errors, 'grid.models entry without a string id'); continue; }
    if (modelIds.has(m.id)) fail(errors, `duplicate model id ${m.id}`);
    modelIds.add(m.id);
    const versions = modelVersions[m.id];
    if (!Array.isArray(versions) || versions.length === 0) {
      fail(errors, `grid.modelVersions has no non-empty version list for model ${m.id}`);
    } else if (new Set(versions).size !== versions.length) {
      fail(errors, `grid.modelVersions[${m.id}] contains duplicates`);
    }
  }
  for (const id of Object.keys(modelVersions)) {
    if (!modelIds.has(id)) fail(errors, `grid.modelVersions names model ${id}, which grid.models does not declare`);
  }
  if (new Set(promptStyles).size !== promptStyles.length) fail(errors, 'grid.promptStyles contains duplicates');
  const tempKeys = temperatures.map(formatTemperature);
  if (new Set(tempKeys).size !== tempKeys.length) {
    fail(errors, 'grid.temperatures contains values that collapse to the same 2-decimal key');
  }

  // ---- the expected coordinate set -------------------------------------------
  // Sorted at every level so the `missingCells` list is itself deterministic.
  const expected = new Map();
  for (const t of [...taskSpecIds].sort()) {
    for (const m of [...modelIds].sort()) {
      for (const v of [...(modelVersions[m] ?? [])].sort()) {
        for (const p of [...promptStyles].sort()) {
          for (const temp of [...temperatures].sort((a, b) => a - b)) {
            for (let s = 0; s < (Number.isInteger(samplesPerCell) ? samplesPerCell : 0); s++) {
              const coord = {
                taskSpec: t, model: m, modelVersion: v, promptStyle: p, temperature: temp, sampleIndex: s,
              };
              expected.set(cellIdOf(coord), coord);
            }
          }
        }
      }
    }
  }

  // ---- the declared cells ----------------------------------------------------
  const declared = new Map();
  const cells = [];
  const rawCells = Array.isArray(manifest.cells) ? manifest.cells : [];
  if (rawCells.length === 0) fail(errors, 'manifest.cells is empty');

  for (const cell of rawCells) {
    if (!cell || typeof cell !== 'object') { fail(errors, 'cells contains a non-object entry'); continue; }
    const derived = cellIdOf(cell);
    if (cell.cellId !== derived) {
      fail(errors, `cell declares cellId ${JSON.stringify(cell.cellId)} but its coordinate derives ${derived}`);
    }
    if (declared.has(derived)) {
      fail(errors, `duplicate cell for coordinate ${derived}`);
      continue;
    }
    declared.set(derived, cell);

    if (!taskSpecIds.has(cell.taskSpec)) fail(errors, `${derived}: taskSpec ${cell.taskSpec} is not in the grid`);
    if (!modelIds.has(cell.model)) fail(errors, `${derived}: model ${cell.model} is not in the grid`);
    else if (!(modelVersions[cell.model] ?? []).includes(cell.modelVersion)) {
      fail(errors, `${derived}: modelVersion ${cell.modelVersion} is not declared for model ${cell.model}`);
    }
    if (!promptStyles.includes(cell.promptStyle)) fail(errors, `${derived}: promptStyle ${cell.promptStyle} is not in the grid`);
    if (!tempKeys.includes(formatTemperature(cell.temperature))) fail(errors, `${derived}: temperature ${cell.temperature} is not in the grid`);

    const taskSpec = taskSpecs.find((t) => t && t.id === cell.taskSpec);
    const files = [];
    const rawFiles = Array.isArray(cell.files) ? cell.files : [];
    if (rawFiles.length === 0) fail(errors, `${derived}: declares no files`);

    for (const f of rawFiles) {
      if (!f || typeof f.path !== 'string' || f.path === '') { fail(errors, `${derived}: file entry without a path`); continue; }
      // Path containment. The manifest is INPUT — possibly from a corpus someone
      // else assembled — so `../../../etc/passwd` is a live shape, and a scorer
      // that reads whatever path it is handed is a file-disclosure primitive
      // wearing an experiment's clothes.
      const abs = resolve(corpusRoot, f.path);
      if (!abs.startsWith(corpusRoot + sep)) {
        fail(errors, `${derived}: file path ${f.path} escapes the corpus directory`);
        continue;
      }
      if (!existsSync(abs) || !statSync(abs).isFile()) { fail(errors, `${derived}: file ${f.path} does not exist`); continue; }

      const bytes = readFileSync(abs);
      if (bytes.length === 0) { fail(errors, `${derived}: file ${f.path} is empty`); continue; }
      const digest = sha256(bytes);
      if (typeof f.sha256 !== 'string' || f.sha256 === '') {
        // Required, not optional. Without content addressing the manifest names
        // files whose bytes can change under it, and a "reproducible" score would
        // be reproducible only until somebody edited the corpus.
        fail(errors, `${derived}: file ${f.path} declares no sha256`);
      } else if (f.sha256.toLowerCase() !== digest) {
        fail(errors, `${derived}: file ${f.path} sha256 mismatch (manifest ${f.sha256}, on disk ${digest})`);
      }

      const ext = extname(f.path).toLowerCase();
      const language = LANG_BY_EXT[ext];
      if (!language) {
        fail(errors, `${derived}: file ${f.path} has extension ${ext || '(none)'}, which no shipped rule language covers`);
        continue;
      }
      if (taskSpec && taskSpec.language && language !== taskSpec.language) {
        fail(errors, `${derived}: file ${f.path} is ${language} but taskSpec ${taskSpec.id} declares ${taskSpec.language}`);
      }
      files.push({ path: slash(f.path), language, sha256: digest, content: bytes.toString('utf8') });
    }

    files.sort((a, b) => a.path.localeCompare(b.path));
    cells.push({ ...cell, cellId: derived, files });
  }

  const missingCells = [...expected.keys()].filter((id) => !declared.has(id)).sort();
  const unexpectedCells = [...declared.keys()].filter((id) => !expected.has(id)).sort();
  if (missingCells.length > 0) {
    fail(errors, `grid is incomplete: ${missingCells.length} of ${expected.size} coordinates have no cell`);
  }
  if (unexpectedCells.length > 0) {
    fail(errors, `${unexpectedCells.length} cell(s) sit at coordinates the grid does not define`);
  }

  cells.sort((a, b) => a.cellId.localeCompare(b.cellId));
  return { errors, missingCells, unexpectedCells, cells, expectedCellCount: expected.size };
}

// ---------------------------------------------------------------------------
// Scoring
//
// The SHIPPED rules, run directly — `allRules` from @vibeguard/rules, the same
// array the analyzer iterates. Not the Analyzer itself, and the reason is the
// DoD: a ScanResponse carries `executionTimeMs`, `generatedAt` and a per-run
// `findingId`, so scoring through it would put three fresh non-deterministic
// values into the output on every run. sec-b1-gen-corpus.mjs strips exactly
// those three for exactly this reason; refusing to create them is simpler than
// remembering to remove them.
//
// The cost is stated rather than hidden: this measures the RULE layer, not the
// analyzer's context-confidence downgrades or its suppression handling, and it
// does not run the cross-file design smells in @vibeguard/analysis-graph at all
// (those need a project index, which a single generated file is not). A cell's
// score here is "what the rules matched", and the output field is named so.
// ---------------------------------------------------------------------------

const RULE_ERRORS = [];

function scoreFile(file, cellId) {
  const ctx = {
    content: file.content,
    lines: file.content.split('\n'),
    language: file.language,
    filePath: file.path,
  };
  const found = [];
  for (const rule of allRules) {
    if (!languageMatches(rule.languages, file.language)) continue;
    let matches;
    try {
      matches = rule.match(ctx);
    } catch (err) {
      // Never swallowed: a rule that throws shrinks the denominator and flatters
      // whichever cell it threw on.
      RULE_ERRORS.push({
        cellId,
        filePath: file.path,
        ruleId: rule.ruleId,
        message: String(err && err.message ? err.message : err),
      });
      continue;
    }
    for (const m of matches) {
      found.push({
        ruleId: rule.ruleId,
        category: rule.category,
        severity: m.severity ?? rule.severity,
        defaultConfidence: rule.defaultConfidence,
        startLine: m.startLine,
        endLine: m.endLine,
      });
    }
  }
  found.sort(
    (a, b) => a.startLine - b.startLine || a.ruleId.localeCompare(b.ruleId) || a.endLine - b.endLine,
  );
  return found;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function tallySeverities(findings) {
  const out = {};
  for (const s of SEVERITY_ORDER) out[s] = 0;
  for (const f of findings) if (Object.prototype.hasOwnProperty.call(out, f.severity)) out[f.severity] += 1;
  return out;
}

/** Sorted [{key, …}] arrays rather than objects: an array has no key order to argue about. */
function groupBy(cells, keyOf) {
  const map = new Map();
  for (const c of cells) {
    const key = keyOf(c);
    let bucket = map.get(key);
    if (!bucket) { bucket = { key, cells: 0, findings: 0, cellsWithAnyFinding: 0, bySeverity: tallySeverities([]) }; map.set(key, bucket); }
    bucket.cells += 1;
    bucket.findings += c.findings.length;
    if (c.findings.length > 0) bucket.cellsWithAnyFinding += 1;
    for (const s of SEVERITY_ORDER) bucket.bySeverity[s] += c.severityCounts[s];
  }
  return [...map.values()].sort((a, b) => String(a.key).localeCompare(String(b.key)));
}

// ---------------------------------------------------------------------------
// Provenance of the SCORING run (not of the corpus).
//
// Shape follows sec-b1-gen-corpus.mjs field-for-field so the three security
// experiments can be compared without a translation layer. `dirtyProduct` is the
// subset under packages/ — the only paths that can change what the rules report,
// so a dirty harness and a dirty engine stay distinguishable.
//
// Deterministic across two consecutive runs by construction: git answers the
// same question the same way when nothing changed in between, and the output
// file itself lands in a gitignored directory so it can never appear in its own
// `dirtyPaths`.
// ---------------------------------------------------------------------------
function readScoringProvenance() {
  let gitSha = 'unknown';
  let dirty = null;
  let dirtyPaths = null;
  let dirtyProduct = null;
  try {
    const r = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
    if (r.status === 0 && typeof r.stdout === 'string') gitSha = r.stdout.trim();
  } catch { /* recorded as unknown */ }
  try {
    const r = spawnSync('git', ['status', '--porcelain'], { encoding: 'utf8' });
    // status !== 0 means git could not answer (not a repo, git absent). Leaving
    // `dirty` null is the honest record: unknown, not clean.
    if (r.status === 0 && typeof r.stdout === 'string') {
      dirtyPaths = r.stdout.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => l.replace(/^\S{1,3}[^\S\r\n]{1,4}/, '')).sort();
      dirty = dirtyPaths.length > 0;
      dirtyProduct = dirtyPaths.filter((p) => p.startsWith('packages/'));
    }
  } catch { /* recorded as null */ }

  let rulesVersion = 'unknown';
  try {
    rulesVersion = JSON.parse(readFileSync(join(REPO_ROOT, 'packages/rules/package.json'), 'utf8')).version;
  } catch { /* recorded as unknown */ }

  return {
    gitSha,
    dirty,
    dirtyPaths,
    dirtyProduct,
    dirtyNote:
      'dirty=true means the tree held uncommitted changes when this scoring ran, so gitSha does not fully identify the rules that produced these counts. dirtyProduct lists the subset under packages/ — the only paths that can change what the rules report.',
    nodeVersion: process.version,
    rulesVersion,
  };
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

/** Everything from manifest path to output STRING. Pure with respect to the filesystem it writes: nothing is written here. */
function buildResult(manifestPathAbs) {
  RULE_ERRORS.length = 0;

  const manifestBytes = readFileSync(manifestPathAbs);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const corpusRoot = dirname(manifestPathAbs);

  const { errors, missingCells, unexpectedCells, cells, expectedCellCount } = validateManifest(manifest, corpusRoot);

  const scored = cells.map((cell) => {
    const perFile = cell.files.map((f) => ({
      path: f.path,
      language: f.language,
      sha256: f.sha256,
      findings: scoreFile(f, cell.cellId),
    }));
    const findings = perFile.flatMap((f) => f.findings);
    const ruleIds = [...new Set(findings.map((f) => f.ruleId))].sort();
    return {
      cellId: cell.cellId,
      taskSpec: cell.taskSpec,
      model: cell.model,
      modelVersion: cell.modelVersion,
      promptStyle: cell.promptStyle,
      temperature: Number(formatTemperature(cell.temperature)),
      sampleIndex: cell.sampleIndex,
      files: perFile.map((f) => ({ path: f.path, language: f.language, sha256: f.sha256, findingCount: f.findings.length })),
      findings,
      findingCount: findings.length,
      distinctRuleIds: ruleIds,
      severityCounts: tallySeverities(findings),
    };
  });

  const origin = manifest.corpusOrigin === 'recorded-sample' ? 'recorded-sample' : manifest.corpusOrigin;
  const isSample = origin === 'recorded-sample';

  const result = {
    schemaVersion: OUTPUT_SCHEMA_VERSION,
    generatedBy: 'sec-prov-gen-corpus.mjs',
    corpusId: typeof manifest.corpusId === 'string' ? manifest.corpusId : 'unknown',
    corpusOrigin: origin ?? 'unknown',
    // ★ The stamp that stops the sample from being quoted as a finding. It is
    // prose, in the file, because whoever opens this JSON in six months will not
    // have the terminal output or this source in front of them.
    resultStatus: isSample ? 'not-an-experimental-result' : 'measurement',
    resultStatusReason: isSample
      ? 'This file was produced from the RECORDED SAMPLE corpus shipped in scripts/fixtures/prov-sample/. Its cells were hand-written to keep the scoring pipeline executable from a fresh checkout; no model generated them and the model ids in it name nothing that exists. Nothing here measures any model, any prompt style or any temperature. Any number quoted from this file as an experimental result is a fabrication.'
      : 'Scored from an externally generated corpus. The generator, its grid and the timestamp are the manifest\'s own; this file records only what the shipped rules matched in the supplied sources.',
    // Echoed, never read from a clock here — see the header on why this script
    // refuses the one clock read sec-b1/sec-b3 allow themselves.
    corpusGeneratedAt: typeof manifest.generatedAt === 'string' ? manifest.generatedAt : null,
    generator: manifest.generator ?? null,
    manifest: {
      path: repoRelative(manifestPathAbs),
      sha256: sha256(manifestBytes),
    },
    scoringProvenance: readScoringProvenance(),
    scoring: {
      engine: '@vibeguard/rules allRules, invoked directly',
      appliesContextConfidence: false,
      appliesSuppressions: false,
      includesCrossFileDesignSmells: false,
      note: 'Rule-layer matches only. The analyzer\'s context-confidence downgrades, its suppression handling and the cross-file design smells in @vibeguard/analysis-graph are all outside this number, because each of them introduces per-run state that would break the byte-identical contract or requires a project index a single generated file cannot supply.',
    },
    grid: manifest.grid ?? null,
    validation: {
      complete: errors.length === 0,
      expectedCellCount,
      declaredCellCount: Array.isArray(manifest.cells) ? manifest.cells.length : 0,
      scoredCellCount: scored.length,
      errors,
      missingCells,
      unexpectedCells,
    },
    ruleErrors: RULE_ERRORS.slice().sort(
      (a, b) => a.cellId.localeCompare(b.cellId) || a.ruleId.localeCompare(b.ruleId) || a.filePath.localeCompare(b.filePath),
    ),
    cells: scored,
    aggregates: {
      byPromptStyle: groupBy(scored, (c) => c.promptStyle),
      byModelVersion: groupBy(scored, (c) => `${c.model}@${c.modelVersion}`),
      byTaskSpec: groupBy(scored, (c) => c.taskSpec),
      byTemperature: groupBy(scored, (c) => formatTemperature(c.temperature)),
    },
  };

  return { json: `${JSON.stringify(result, null, 2)}\n`, result };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { manifest: null, out: null, selftest: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--selftest') args.selftest = true;
    else if (a === '--manifest') args.manifest = argv[++i];
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--help' || a === '-h') args.help = true;
    else { args.unknown = a; }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  process.stdout.write(
    'sec-prov-gen-corpus.mjs — score an externally generated AI-provenance grid\n\n' +
      '  --manifest <path>   manifest.json describing the grid and its sources\n' +
      '  --out <path>        output file (default security-experiment/_results/prov-<corpusId>.json)\n' +
      '  --selftest          run the pipeline twice over the recorded sample and byte-compare\n',
  );
  process.exit(0);
}
if (args.unknown) {
  process.stderr.write(`unknown argument: ${args.unknown}\n`);
  process.exit(2);
}

if (args.selftest) {
  // ★ The DoD, executed. Two full pipeline runs — manifest read, validation,
  // scoring, git provenance, serialisation — byte-compared. Not two calls to a
  // helper: the claim is about the program.
  const manifestAbs = resolve(REPO_ROOT, args.manifest ?? SAMPLE_MANIFEST);
  const a = buildResult(manifestAbs).json;
  const b = buildResult(manifestAbs).json;
  const ha = sha256(Buffer.from(a, 'utf8'));
  const hb = sha256(Buffer.from(b, 'utf8'));
  process.stdout.write('# sec-prov-gen-corpus --selftest\n');
  process.stdout.write(`manifest: ${repoRelative(manifestAbs)}\n`);
  process.stdout.write(`run 1: ${a.length} bytes  sha256 ${ha}\n`);
  process.stdout.write(`run 2: ${b.length} bytes  sha256 ${hb}\n`);
  if (a !== b) {
    // Report WHERE, not just THAT. A diff that only says "differs" costs an
    // afternoon of bisecting a 100 KB JSON.
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    process.stderr.write(
      `\nFAIL: output is not byte-identical on re-run. First difference at byte ${i}:\n` +
        `  run 1: ${JSON.stringify(a.slice(Math.max(0, i - 60), i + 60))}\n` +
        `  run 2: ${JSON.stringify(b.slice(Math.max(0, i - 60), i + 60))}\n`,
    );
    process.exit(1);
  }
  // CRLF would survive a byte-compare (both runs would carry it) and still break
  // the contract, so it is asserted separately rather than assumed.
  if (a.includes('\r')) {
    process.stderr.write('\nFAIL: output contains a CR byte; the contract is LF-only.\n');
    process.exit(1);
  }
  process.stdout.write('\nOK: byte-identical across two full pipeline runs, LF-only.\n');
  process.exit(0);
}

const manifestRel = args.manifest ?? SAMPLE_MANIFEST;
const manifestAbs = resolve(REPO_ROOT, manifestRel);
if (!existsSync(manifestAbs)) {
  process.stderr.write(`manifest not found: ${manifestRel}\n`);
  process.exit(2);
}

const { json, result } = buildResult(manifestAbs);

const outRel = args.out ?? `${RESULTS_DIR}/prov-${result.corpusId}.json`;
const outAbs = resolve(REPO_ROOT, outRel);
mkdirSync(dirname(outAbs), { recursive: true });
writeFileSync(outAbs, json);

// ---- console summary -------------------------------------------------------
if (result.corpusOrigin === 'recorded-sample') {
  process.stderr.write(
    '\n' +
      '================================================================\n' +
      'RECORDED SAMPLE — NOT AN EXPERIMENTAL RESULT\n' +
      'The cells scored below were hand-written to keep this pipeline\n' +
      'runnable. No model generated them. Do not quote these numbers.\n' +
      '================================================================\n\n',
  );
}
process.stdout.write(`# PROV scoring (${result.corpusOrigin}, corpus ${result.corpusId})\n`);
process.stdout.write(`cells: ${result.validation.scoredCellCount} of ${result.validation.expectedCellCount} expected\n`);
for (const c of result.cells) {
  process.stdout.write(
    `  ${c.cellId.padEnd(52)} ${String(c.findingCount).padStart(3)} finding(s)` +
      `${c.distinctRuleIds.length ? `  [${c.distinctRuleIds.join(', ')}]` : ''}\n`,
  );
}
process.stdout.write('\nby prompt style:\n');
for (const g of result.aggregates.byPromptStyle) {
  process.stdout.write(`  ${String(g.key).padEnd(32)} ${g.findings} finding(s) over ${g.cells} cell(s)\n`);
}
process.stdout.write(`\nrule errors: ${result.ruleErrors.length}\n`);
for (const e of result.ruleErrors.slice(0, 10)) process.stdout.write(`  ${e.ruleId} ${e.cellId}: ${e.message}\n`);
process.stdout.write(`\nwritten: ${outRel}\n`);

if (!result.validation.complete) {
  process.stderr.write(`\nFAIL: manifest rejected (${result.validation.errors.length} error(s)):\n`);
  for (const e of result.validation.errors.slice(0, 20)) process.stderr.write(`  - ${e}\n`);
  if (result.validation.errors.length > 20) {
    process.stderr.write(`  … ${result.validation.errors.length - 20} more (full list in ${outRel})\n`);
  }
  process.stderr.write('\nThe report above was still written, errors included: a rejected manifest\n');
  process.stderr.write('should leave a machine-readable record of WHY it was rejected.\n');
  process.exit(1);
}
