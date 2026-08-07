#!/usr/bin/env node
// validate-observation — check an observation record against observation.schema.json,
// and then against the invariants the schema cannot state.
//
//   node compiler/schema/validate-observation.mjs <path|dir>...
//   node compiler/schema/validate-observation.mjs --capability
//   node compiler/schema/validate-observation.mjs <dir> --expect-invalid
//   node compiler/schema/validate-observation.mjs <dir> --allow-empty
//
// WHY THERE IS A SECOND HALF
//
// compiler/driver/lib/jsonschema.mjs is the in-repo validator, and it implements
// exactly fifteen draft-07 keywords and refuses the rest by name. That refusal is
// the right design -- a half-checked schema is worse than none -- but it means the
// schema alone cannot say most of what makes an observation record honest.
// `--capability` prints, keyword by keyword, what the schema uses and whether the
// in-repo validator implements it, and the test file asserts that report against
// the validator's real behaviour rather than against this comment. What it cannot
// express, in the shapes this schema needs:
//
//   minItems      -- "at least one observation point"
//   oneOf / if    -- "reached=false requires a reason", "VERIFIED_CLEAN forbids findings"
//   $data / links -- "history[].point names a declared observationPoint"
//   (nothing)     -- "the number 1.0 is not an integer", which JSON.parse has
//                    already erased by the time any validator sees the value
//
// So the rules below are code, each with an id, each reported by id. They are not
// extras: OBS-S07 is the rule that stops this whole directory writing CLEAN over
// something it never looked at, and it is not expressible in draft-07 at all.
//
// EXIT CODES -- interfaces.md section 7, unchanged.
//   0 every document validated (or, under --expect-invalid, every document failed)
//   1 a prerequisite is missing. Never a skip: see ALLOW_SKIP below
//   3 nothing was checked, or a file could not be read. Never conflated with 0
//   4 a document is malformed -- schema violation or a semantic rule
//
// SKIP IS NOT PASS. A file this runner cannot parse is a malformed record (4), not
// a skip. The only authorised skip is the environment variable named in ALLOW_SKIP,
// and when it is used every skipped file is listed by name on stdout.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';
import { validate as validateSchema, formatErrors } from '../driver/lib/jsonschema.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = join(HERE, 'observation.schema.json');
const ALLOW_SKIP = 'OBSERVATION_VALIDATE_ALLOW_SKIP';

export const EXIT_OK = 0;
export const EXIT_TOOL_FAILED = 1;
export const EXIT_INCOMPLETE = 3;
export const EXIT_INTEGRITY = 4;

// ── the keyword subset ──────────────────────────────────────────────────────
//
// A mirror of the SUPPORTED set in compiler/driver/lib/jsonschema.mjs, which does
// not export it. A mirror can drift, so it is not trusted: the test file probes
// the real validator with each keyword below and with a keyword deliberately left
// out, and fails if this list and that behaviour disagree.
export const MIRRORED_SUPPORTED_KEYWORDS = Object.freeze([
  '$schema', '$id', 'title', 'description', 'default', 'definitions',
  'type', 'const', 'enum', 'required', 'properties', 'additionalProperties',
  'items', 'pattern', '$ref',
]);

/** Every keyword the schema actually uses, in document order, de-duplicated. */
export function keywordsUsedBy(schema) {
  const seen = new Set();
  const walk = (node, insideProperties) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach((n) => walk(n, false)); return; }
    for (const [key, value] of Object.entries(node)) {
      // Under `properties` and `definitions` the keys are names, not keywords.
      if (!insideProperties) seen.add(key);
      walk(value, key === 'properties' || key === 'definitions');
    }
  };
  walk(schema, false);
  return [...seen].sort();
}

export function capabilityReport(schema) {
  const supported = new Set(MIRRORED_SUPPORTED_KEYWORDS);
  return keywordsUsedBy(schema).map((keyword) => ({
    keyword,
    supported: supported.has(keyword),
  }));
}

// ── semantic rules ──────────────────────────────────────────────────────────

const STATES = ['PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED'];

/** interfaces.md section 7 mapped onto the five verdicts. */
const VERDICT_EXIT = {
  VERIFIED_CLEAN: 0,
  FINDINGS_PRESENT: 2,
  VERIFICATION_INCOMPLETE: 3,
  UNSUPPORTED: 3,
  EVIDENCE_MISMATCH: 4,
};

/**
 * A string that names one machine rather than a fixture. Written as shapes, not
 * as a list of directory names, for the same reason scripts/check-disclosure-shape.mjs
 * is: the next one is spelled in a way nobody enumerated.
 */
const ABSOLUTE_SHAPES = [
  /^[/\\]/,                      // leading separator
  /[A-Za-z]:[\\/]/,              // a drive letter anywhere
  /(?:^|[\s"'(=])~[/\\]/,        // a home-directory shorthand
  /(?:^|[\s"'(=])\/[A-Za-z_.]/,  // an embedded rooted path
];

function walkStrings(node, path, out) {
  if (typeof node === 'string') { out.push([path, node]); return; }
  if (Array.isArray(node)) { node.forEach((n, i) => walkStrings(n, `${path}/${i}`, out)); return; }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) walkStrings(v, `${path}/${k}`, out);
  }
}

function walkNumbers(node, path, out) {
  if (typeof node === 'number') { out.push([path, node]); return; }
  if (Array.isArray(node)) { node.forEach((n, i) => walkNumbers(n, `${path}/${i}`, out)); return; }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) walkNumbers(v, `${path}/${k}`, out);
  }
}

/**
 * The invariants draft-07 cannot state, or that this repository's validator
 * subset cannot state. Each returns findings tagged with its rule id.
 *
 * @param {object} doc a document that has ALREADY passed the schema. These rules
 *   assume the shapes exist; they are about what the shapes may say.
 * @param {string} rawText the bytes as read, needed by OBS-S10.
 * @returns {{rule: string, message: string}[]}
 */
export function semanticErrors(doc, rawText = '') {
  const errs = [];
  const add = (rule, message) => errs.push({ rule, message });
  const points = Array.isArray(doc.observationPoints) ? doc.observationPoints : [];
  const props = Array.isArray(doc.properties) ? doc.properties : [];
  const findings = Array.isArray(doc.findings) ? doc.findings : [];
  const layers = doc.layers ?? {};
  const verdict = doc.verdict ?? {};

  // OBS-S01 every history entry names a declared observation point.
  const pointIds = new Set(points.map((p) => p.id));
  for (const prop of props) {
    for (const entry of prop.history ?? []) {
      if (!pointIds.has(entry.point)) {
        add('OBS-S01', `property \`${prop.id}\` history[${entry.index}] names point \`${entry.point}\`, which is not declared in observationPoints`);
      }
    }
  }

  // OBS-S02 ids are unique. Two points with one id makes OBS-S01 meaningless.
  const dupe = (list, what) => {
    const seen = new Set();
    for (const id of list) {
      if (seen.has(id)) add('OBS-S02', `duplicate ${what} id \`${id}\``);
      seen.add(id);
    }
  };
  dupe(points.map((p) => p.id), 'observationPoint');
  dupe(props.map((p) => p.id), 'property');

  // OBS-S03 history index is 0..n-1 in array order. Array order is significant
  // (interfaces.md section 5 rule 2) and an index that disagrees with it means a
  // reader who sorts and a reader who does not get different histories.
  for (const prop of props) {
    (prop.history ?? []).forEach((entry, i) => {
      if (entry.index !== i) {
        add('OBS-S03', `property \`${prop.id}\` history[${i}] carries index ${entry.index}`);
      }
    });
  }

  // OBS-S04 finalState is the last state in the history, or NOT_OBSERVED for an
  // empty one. A finalState that disagrees with the history is the record
  // summarising itself wrongly, which is the thing a reader will actually read.
  for (const prop of props) {
    const hist = prop.history ?? [];
    const last = hist.length ? hist[hist.length - 1].state : 'NOT_OBSERVED';
    if (prop.finalState !== last) {
      add('OBS-S04', `property \`${prop.id}\` says finalState ${prop.finalState} but its history ends ${last}`);
    }
  }

  // OBS-S05 the transitions have to be possible. LOST is defined as missing where
  // it had been PRESENT, and REINTRODUCED as PRESENT again after LOST; a history
  // that opens with either is using the word for something else.
  for (const prop of props) {
    let everPresent = false;
    let everLost = false;
    for (const entry of prop.history ?? []) {
      if (entry.state === 'LOST' && !everPresent) {
        add('OBS-S05', `property \`${prop.id}\` history[${entry.index}] is LOST with no preceding PRESENT`);
      }
      if (entry.state === 'REINTRODUCED' && !everLost) {
        add('OBS-S05', `property \`${prop.id}\` history[${entry.index}] is REINTRODUCED with no preceding LOST`);
      }
      if (entry.state === 'PRESENT' || entry.state === 'REINTRODUCED') everPresent = true;
      if (entry.state === 'LOST') everLost = true;
    }
  }

  // OBS-S06 a truncated history cannot be clean. interfaces.md section 3: a
  // component that stops at the first PRESENT -> LOST reports a loss a later pass
  // undid. The mirror of that is also true -- a history cut short before the end
  // may have missed the loss -- so neither direction may be called clean.
  for (const prop of props) {
    if (prop.historyComplete === false && prop.verdict === 'VERIFIED_CLEAN') {
      add('OBS-S06', `property \`${prop.id}\` has an incomplete history and still claims VERIFIED_CLEAN`);
    }
  }

  // OBS-S07 the honest verdict. This is the rule the directory exists for.
  if (verdict.state === 'VERIFIED_CLEAN') {
    const why = [];
    if (findings.length) why.push(`${findings.length} finding(s) are present`);
    if ((verdict.unobserved ?? []).length) why.push(`verdict.unobserved lists ${verdict.unobserved.length} item(s)`);
    for (const p of points) if (p.reached === false) why.push(`observation point \`${p.id}\` was not reached`);
    for (const prop of props) {
      for (const entry of prop.history ?? []) {
        if (entry.state === 'NOT_OBSERVED') why.push(`property \`${prop.id}\` is NOT_OBSERVED at \`${entry.point}\``);
      }
      if (prop.finalState === 'NOT_OBSERVED') why.push(`property \`${prop.id}\` ends NOT_OBSERVED`);
      if (prop.verdict && prop.verdict !== 'VERIFIED_CLEAN') why.push(`property \`${prop.id}\` is ${prop.verdict}`);
    }
    for (const name of ['compile', 'link', 'artifact']) {
      if (layers[name] && layers[name].observed === false) why.push(`the ${name} layer was not observed`);
    }
    if (layers.link && (layers.link.ltoMode === 'full' || layers.link.ltoMode === 'thin') && layers.link.backendObserved === false) {
      why.push(`an LTO backend ran (ltoMode ${layers.link.ltoMode}) and its passes were not observed`);
    }
    for (const chk of layers.artifact?.checks ?? []) {
      if (chk.result === 'NOT_OBSERVED') why.push(`artefact requirement \`${chk.require}\` was not observed`);
    }
    for (const w of why) add('OBS-S07', `VERIFIED_CLEAN is not available: ${w}`);
  }

  // OBS-S08 the verdict and the exit code are one decision, not two.
  if (verdict.state in VERDICT_EXIT && verdict.exitCode !== VERDICT_EXIT[verdict.state]) {
    add('OBS-S08', `verdict ${verdict.state} must carry exit code ${VERDICT_EXIT[verdict.state]}, not ${verdict.exitCode}`);
  }

  // OBS-S09 the control discipline. interfaces.md section 4: a measurement whose
  // control also fell to zero is a broken measurement, not a finding. Measured
  // for real -- an executable LTO link internalised and inlined the control away,
  // and the run that reported the subject lost would have reported it lost
  // whatever the subject did.
  for (const prop of props) {
    const c = prop.control;
    if (!c) continue;
    const dead = c.count?.callSites === 0 || c.state === 'LOST' || c.state === 'ABSENT';
    if (dead && verdict.state === 'FINDINGS_PRESENT') {
      add('OBS-S09', `the control \`${c.unit}\` did not survive (state ${c.state}, callSites ${c.count?.callSites}); this is EVIDENCE_MISMATCH, not FINDINGS_PRESENT`);
    }
    if (dead && verdict.state === 'VERIFIED_CLEAN') {
      add('OBS-S09', `the control \`${c.unit}\` did not survive (state ${c.state}, callSites ${c.count?.callSites}); a measurement that cannot see its own control cannot report clean`);
    }
    if (c.state === 'NOT_OBSERVED' && verdict.state === 'FINDINGS_PRESENT') {
      add('OBS-S09', `the control \`${c.unit}\` was never observed, so the finding has no control`);
    }
  }

  // OBS-S10 every number is an integer (interfaces.md section 5 rule 4). Two
  // passes, because neither alone is enough: JSON.parse has already turned 1.0
  // into 1 by the time a value can be inspected, so the written form is checked
  // in the text -- with string literals removed first, or a version like "18.1.3"
  // would be read as a number.
  const numbers = [];
  walkNumbers(doc, '', numbers);
  for (const [path, n] of numbers) {
    if (!Number.isInteger(n)) add('OBS-S10', `${path || '(root)'} is ${n}; a ratio is a pair {num, den}, never a float`);
  }
  if (rawText) {
    const stripped = rawText.replace(/"(?:[^"\\]|\\.)*"/g, '""');
    const written = stripped.match(/-?\d+(?:\.\d+|[eE][+-]?\d+)/g);
    if (written) add('OBS-S10', `written as a non-integer literal: ${[...new Set(written)].join(', ')}`);
  }

  // OBS-S11 no absolute paths anywhere (interfaces.md section 5). A record that
  // names one machine's filesystem is both a disclosure and useless to anyone else.
  const strings = [];
  walkStrings(doc, '', strings);
  for (const [path, s] of strings) {
    if (path.startsWith('/context/')) continue; // provenance, still checked below
    for (const shape of ABSOLUTE_SHAPES) {
      if (shape.test(s)) { add('OBS-S11', `${path} contains an absolute path: ${JSON.stringify(s.slice(0, 80))}`); break; }
    }
  }
  for (const [path, s] of strings) {
    if (!path.startsWith('/context/')) continue;
    for (const shape of ABSOLUTE_SHAPES) {
      if (shape.test(s)) { add('OBS-S11', `${path} contains an absolute path: ${JSON.stringify(s.slice(0, 80))}`); break; }
    }
  }

  // OBS-S12 a point that was not reached says why, in the tool's words.
  for (const p of points) {
    if (p.reached === false && !(typeof p.unreachedReason === 'string' && p.unreachedReason.trim())) {
      add('OBS-S12', `observation point \`${p.id}\` was not reached and gives no reason`);
    }
  }

  // OBS-S13 findings and the verdict agree about whether anything was found.
  if (findings.length && verdict.state === 'UNSUPPORTED') {
    add('OBS-S13', `${findings.length} finding(s) recorded under an UNSUPPORTED verdict; a configuration outside the envelope has not been checked, so it has no findings`);
  }
  if (!findings.length && verdict.state === 'FINDINGS_PRESENT') {
    add('OBS-S13', 'verdict FINDINGS_PRESENT with an empty findings array');
  }

  // OBS-S14 a finding must point at something the record declares.
  for (const f of findings) {
    if (f.point != null && !pointIds.has(f.point)) {
      add('OBS-S14', `finding ${f.id} names point \`${f.point}\`, which is not declared`);
    }
    if (f.property != null && !props.some((p) => p.id === f.property)) {
      add('OBS-S14', `finding ${f.id} names property \`${f.property}\`, which is not declared`);
    }
  }

  return errs;
}

/**
 * Schema first, then the semantic rules. The semantic rules are skipped when the
 * schema already failed, because they assume shapes that are not there yet and
 * would report a second, misleading cause for one defect.
 */
export function validateDocument(schema, doc, rawText = '') {
  const schemaErrors = validateSchema(schema, doc);
  const unsupported = schemaErrors.filter((e) => e.message.includes('unsupported keyword'));
  if (unsupported.length) {
    return {
      ok: false,
      kind: 'validator-mismatch',
      errors: unsupported.map((e) => `${e.pointer || '(root)'}: ${e.message}`),
    };
  }
  if (schemaErrors.length) {
    return { ok: false, kind: 'schema', errors: formatErrors(schemaErrors).split('\n') };
  }
  const sem = semanticErrors(doc, rawText);
  if (sem.length) {
    return { ok: false, kind: 'semantic', errors: sem.map((e) => `${e.rule}: ${e.message}`), rules: sem.map((e) => e.rule) };
  }
  return { ok: true, kind: 'ok', errors: [] };
}

// ── the runner ──────────────────────────────────────────────────────────────

function collect(target, out) {
  let st;
  try {
    st = statSync(target);
  } catch (err) {
    throw Object.assign(new Error(`cannot stat ${target}: ${err.code}`), { incomplete: true });
  }
  if (st.isDirectory()) {
    for (const name of readdirSync(target).sort()) collect(join(target, name), out);
    return out;
  }
  if (target.endsWith('.json')) out.push(target);
  return out;
}

export function loadSchema(path = SCHEMA_PATH) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function run(argv, log = console.log, errLog = console.error) {
  const expectInvalid = argv.includes('--expect-invalid');
  const allowEmpty = argv.includes('--allow-empty');
  const capability = argv.includes('--capability');
  const targets = argv.filter((a) => !a.startsWith('--'));

  let schema;
  try {
    schema = loadSchema();
  } catch (err) {
    errLog(`FATAL: the schema could not be read (${err.message}). This is a missing prerequisite, not a skip.`);
    return EXIT_TOOL_FAILED;
  }

  if (capability) {
    const report = capabilityReport(schema);
    const missing = report.filter((r) => !r.supported);
    log('keyword                supported by compiler/driver/lib/jsonschema.mjs');
    for (const r of report) log(`${r.keyword.padEnd(22)} ${r.supported ? 'yes' : 'NO'}`);
    log(`inputs=${report.length} checked=${report.length} skipped=0`);
    if (missing.length) {
      errLog(`the schema uses ${missing.length} keyword(s) the in-repo validator refuses: ${missing.map((m) => m.keyword).join(', ')}`);
      errLog('a schema that is never really checked is worse than no schema; either drop the keyword or extend the validator.');
      return EXIT_INTEGRITY;
    }
    return EXIT_OK;
  }

  const skipAuthorised = process.env[ALLOW_SKIP] === '1';
  const files = [];
  const unreadable = [];
  for (const t of targets) {
    try {
      collect(t, files);
    } catch (err) {
      if (skipAuthorised) { unreadable.push(t); continue; }
      errLog(`FATAL: ${err.message}`);
      log('inputs=0 checked=0 skipped=0');
      return EXIT_INCOMPLETE;
    }
  }

  let checked = 0;
  const skipped = [...unreadable];
  const failures = [];
  const unexpectedPasses = [];

  for (const file of files) {
    const shown = relative(process.cwd(), file).split(sep).join('/') || file;
    let rawText;
    try {
      rawText = readFileSync(file, 'utf8');
    } catch (err) {
      if (skipAuthorised) { skipped.push(shown); continue; }
      errLog(`FATAL: cannot read ${shown} (${err.code})`);
      log(`inputs=${files.length} checked=${checked} skipped=${skipped.length}`);
      return EXIT_INCOMPLETE;
    }
    checked += 1;
    let doc;
    try {
      doc = JSON.parse(rawText);
    } catch (err) {
      // Not a skip: a record that will not parse is a malformed record.
      failures.push({ file: shown, kind: 'parse', errors: [err.message] });
      continue;
    }
    const result = validateDocument(schema, doc, rawText);
    if (expectInvalid) {
      if (result.ok) unexpectedPasses.push(shown);
      else log(`  rejected ${shown} (${result.kind}): ${result.errors[0]}`);
    } else if (!result.ok) {
      failures.push({ file: shown, ...result });
    }
  }

  log(`inputs=${files.length} checked=${checked} skipped=${skipped.length}`);
  if (skipped.length) {
    log('skipped by name (authorised):');
    for (const s of skipped) log(`  ${s}`);
  }

  if (files.length === 0) {
    if (!allowEmpty) {
      errLog('nothing was checked. An empty scan is not a pass; pass --allow-empty to authorise one.');
      return EXIT_INCOMPLETE;
    }
    log('empty run explicitly authorised with --allow-empty');
    return EXIT_OK;
  }

  if (expectInvalid) {
    if (unexpectedPasses.length) {
      errLog(`these documents were expected to fail and did not: ${unexpectedPasses.join(', ')}`);
      return EXIT_INTEGRITY;
    }
    log(`all ${checked} document(s) rejected, as expected`);
    return EXIT_OK;
  }

  if (failures.length) {
    for (const f of failures) {
      errLog(`FAIL ${f.file} (${f.kind})`);
      for (const e of f.errors) errLog(`  ${e}`);
    }
    errLog(`${failures.length} of ${checked} document(s) are malformed`);
    return EXIT_INTEGRITY;
  }
  log(`all ${checked} document(s) valid`);
  return EXIT_OK;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  process.exit(run(process.argv.slice(2)));
}
