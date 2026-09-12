/**
 * The pin-family table, checked against the tracked rows it claims to summarise.
 *
 * ../pin-families.json says, for each (property, disappearance shape, repair
 * candidate), whether the candidate is measured to bring the property back. A
 * table like that is worth nothing if its numbers were typed in: the whole point
 * of the file is to be the place a reader trusts instead of re-deriving, so
 * these tests re-derive. Every `measured-*` row cites a claim, every claim is a
 * function of the tracked rows in ../data/ (../lib/pin-families.mjs), and the
 * number in the file has to equal the number that function returns.
 *
 * The same discipline is applied to the things that are NOT numbers:
 *
 *   - every property id must be one properties.json defines, so a row cannot
 *     invent a property;
 *   - every routing target must be a rule id that exists in packages/rules, and
 *     the recall it quotes must be a sentence that is actually in the file it
 *     names, quoted with its scope;
 *   - every quote a row carries must be in the file it names, so a README
 *     rewritten from under this table fails here rather than silently;
 *   - the prose in ../PIN-FAMILIES.md must print the same ratios as the table;
 *   - and the counts that prose makes ABOUT THE TABLE ITSELF -- how many rows,
 *     how many route to a rule whose scope does not cover the shape, how many
 *     of them a human typed rather than this test recomputing -- are recomputed
 *     too. They were the only numbers in the deliverable that nothing could
 *     fail on, and two of them were wrong;
 *   - "never comes back" must come from the gate, not from a row that asserts it.
 *
 * No compiler. Reading the corpus text and the tracked rows is all that happens.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  STATUSES, NOT_REPAIRABLE_BASES, APPLIES, CLAIM_IDS, CLAIMS, PROVENANCES,
  recompute, validateTable, interventionVerdict, shapeVerdicts, byShape,
  rowProvenance, tableCensus,
  parsePipeline, renderPipeline, leaves, withoutLeaf, prefixLeaves,
} from '../lib/pin-families.mjs';
import { absolutePathHits } from '../lib/provenance.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const REPO = path.resolve(LANE, '..', '..', '..');
const TABLE_PATH = path.join(LANE, 'pin-families.json');
const TABLE_TEXT = readFileSync(TABLE_PATH, 'utf8');
const TABLE = JSON.parse(TABLE_TEXT);
const MD = readFileSync(path.join(LANE, 'PIN-FAMILIES.md'), 'utf8');
const CORPUS = path.resolve(LANE, '..', 'ai-generated', 'generated-corpus', 'r2');

const rowsByCc = {
  'clang-18': JSON.parse(readFileSync(path.join(LANE, 'data', 'r2-repair-rows.json'), 'utf8')),
  'gcc-13': JSON.parse(readFileSync(path.join(LANE, 'data', 'r2-repair-rows-gcc-13.json'), 'utf8')),
};
const find = JSON.parse(readFileSync(path.resolve(LANE, '..', 'ai-generated', 'data', 'r2-build-rows.json'), 'utf8'));
const sources = readdirSync(CORPUS).filter((f) => f.endsWith('.c'))
  .map((f) => ({ id: f.replace(/\.c$/, ''), src: readFileSync(path.join(CORPUS, f), 'utf8') }));
const DATA = { rowsByCc, find, sources };

/** Comment leaders and line wrapping are formatting; a quote is checked through them. */
const norm = (s) => String(s).replace(/^[ \t]*(?:\/\/|\*)[ \t]?/gm, '').replace(/\s+/g, ' ').trim();
const fileText = (rel) => readFileSync(path.join(REPO, rel), 'utf8');
const ratio = (v) => `${v.num}/${v.den}`;
const measured = (r) => r.status === 'measured-retained' || r.status === 'measured-not-retained';

test('the table is well formed by its own validator', () => {
  assert.deepEqual(validateTable(TABLE), []);
});

test('the status words are exactly the four, and nothing else is used', () => {
  assert.deepEqual([...STATUSES], ['measured-retained', 'measured-not-retained', 'unmeasured', 'not-repairable-in-compiler']);
  for (const r of TABLE.rows) assert.ok(STATUSES.includes(r.status), `${r.shape}/${r.candidate}: ${r.status}`);
  // and the table actually uses more than one of them, or it is not a classification
  assert.ok(new Set(TABLE.rows.map((r) => r.status)).size >= 3, 'a table with one status word is a list');
});

test('EVERY measured claim recomputes from the tracked rows, and drift fails here', () => {
  let checked = 0;
  for (const r of TABLE.rows) {
    for (const block of [r.evidence, r.control]) {
      if (!block?.cite) continue;
      const got = recompute(block.cite, DATA);
      assert.deepEqual(got, block.value,
        `${r.property} / ${r.shape} / ${r.candidate}: the table says ${ratio(block.value)} for ${block.cite.claim}`
        + `${block.cite.cc ? ` (${block.cite.cc}` : ''}${block.cite.opt ? ` ${block.cite.opt}` : ''}`
        + `${block.cite.scen ? ` ${block.cite.scen}` : ''}${block.cite.counter ? ` ${block.cite.counter}` : ''}${block.cite.cc ? ')' : ''}`
        + `, the rows say ${ratio(got)}`);
      assert.ok(got.den > 0, `${r.shape}: a claim with an empty denominator proves nothing`);
      checked++;
    }
  }
  // A vacuous pass would be a table with no cited claims at all.
  assert.ok(checked >= 20, `only ${checked} claims were recomputed; the table should cite far more`);
});

test('every measured-* row is tracked, and no lab run carries a measured word', () => {
  for (const r of TABLE.rows) {
    if (measured(r)) {
      assert.equal(r.evidence?.tracked, true, `${r.shape}/${r.candidate} is ${r.status} without tracked evidence`);
      assert.ok(!r.labObservation, `${r.shape}/${r.candidate}: a lab run cannot support ${r.status}`);
      assert.ok(!r.intervention, `${r.shape}/${r.candidate}: an intervention is one run and cannot support ${r.status}`);
    }
  }
  // and the distinction is actually exercised: something in the table IS a lab run
  assert.ok(TABLE.rows.some((r) => r.labObservation || r.intervention), 'no row records a lab observation');
});

test('"never comes back" comes from the gate and from nowhere else', () => {
  const base = { positionsTried: 2, asmChannelRead: true, irChannelRead: true, cameBackAt: [], replayReproducedLoss: true, controlHeld: true };
  assert.equal(interventionVerdict(base).verdict, 'NEVER_CAME_BACK');
  assert.equal(interventionVerdict({ ...base, positionsTried: 1 }).verdict, 'NOT_ENOUGH_EVIDENCE');
  assert.equal(interventionVerdict({ ...base, positionsTried: 0, asmChannelRead: false }).verdict, 'NOT_ENOUGH_EVIDENCE');
  assert.equal(interventionVerdict({ ...base, asmChannelRead: false }).verdict, 'NOT_ENOUGH_EVIDENCE');
  assert.equal(interventionVerdict({ ...base, irChannelRead: false }).verdict, 'NOT_ENOUGH_EVIDENCE');
  assert.equal(interventionVerdict({ ...base, cameBackAt: [59] }).verdict, 'CAME_BACK');
  assert.equal(interventionVerdict({ ...base, replayReproducedLoss: false }).verdict, 'BROKEN_MEASUREMENT');
  assert.equal(interventionVerdict({ ...base, controlHeld: false }).verdict, 'BROKEN_MEASUREMENT');
  assert.equal(interventionVerdict(undefined).verdict, 'BROKEN_MEASUREMENT');
  // the two conditions the brief is about, spelled out: one position is not enough,
  // and an IR-only reading is not enough
  assert.match(interventionVerdict({ ...base, positionsTried: 1 }).why, /at least 2/);
  assert.match(interventionVerdict({ ...base, asmChannelRead: false }).why, /asm channel/);
  // and every intervention block in the table agrees with the gate
  for (const r of TABLE.rows) {
    if (!r.intervention) continue;
    assert.equal(interventionVerdict(r.intervention).verdict, r.intervention.verdict, `${r.shape}/${r.candidate}`);
    if (r.intervention.verdict === 'NEVER_CAME_BACK') {
      assert.ok(r.intervention.positionsTried >= 2 && r.intervention.asmChannelRead === true,
        `${r.shape}/${r.candidate}: NEVER_CAME_BACK without two positions and the asm channel`);
    }
  }
});

test('every property id is one compiler/schema/properties.json defines', () => {
  const props = JSON.parse(fileText('compiler/schema/properties.json'));
  const known = new Set((Array.isArray(props.properties) ? props.properties : Object.values(props.properties)).map((p) => p.id));
  assert.ok(known.size > 0);
  for (const r of TABLE.rows) {
    assert.ok(known.has(r.property), `${r.property} is not a property id; properties.json is the vocabulary and this lane does not extend it`);
  }
});

test('every routing target is a rule that exists, with its scope and its recall stated', () => {
  const ruleSrc = readdirSync(path.join(REPO, 'packages', 'rules', 'src', 'rules'))
    .filter((f) => f.endsWith('.ts'))
    .map((f) => fileText(path.join('packages', 'rules', 'src', 'rules', f))).join('\n');
  let named = 0;
  for (const r of TABLE.rows) {
    const t = r.routesTo;
    if (!t) continue;
    if (t.rule === 'none') { assert.ok(t.whyNone?.length > 20, `${r.shape}: "none" without a reason`); continue; }
    named++;
    assert.ok(ruleSrc.includes(`'${t.rule}'`), `${t.rule} is not a ruleId in packages/rules/src/rules`);
    assert.ok(APPLIES.includes(t.appliesToThisShape), `${r.shape}: appliesToThisShape ${t.appliesToThisShape}`);
    if (t.recallVerified) {
      assert.ok(norm(fileText(t.recallSource)).includes(norm(t.recallQuote)),
        `${r.shape}: the recall quote is not in ${t.recallSource} any more`);
      assert.ok(t.recallScope.length > 20, `${r.shape}: a recall without a scope sentence`);
      if (t.recallAlsoQuoted) {
        const also = norm(fileText(t.recallAlsoQuoted.source));
        assert.ok(also.includes(norm(t.recallAlsoQuoted.quote)), `${r.shape}: ${t.recallAlsoQuoted.quote}`);
        assert.ok(also.includes(norm(t.recallAlsoQuoted.scopeQuote)), `${r.shape}: ${t.recallAlsoQuoted.scopeQuote}`);
      }
    } else {
      assert.ok(t.recallUnverifiedWhy?.length > 20, `${r.shape}: an unverified recall with no reason`);
    }
  }
  assert.ok(named >= 3, 'no row routes anywhere, so the routing half of the table is untested');
});

test('a shape that no candidate retains says where it goes instead', () => {
  const v = shapeVerdicts(TABLE);
  for (const [key, g] of Object.entries(v)) {
    if (g.verdict === 'repairable-in-compiler') { assert.ok(g.retainedBy.length > 0, key); continue; }
    assert.ok(g.routesTo.length > 0, `${key}: ${g.verdict} with nothing to route to`);
  }
  // the table's own summary, as a shape: at least one of each disposition
  const kinds = new Set(Object.values(v).map((g) => g.verdict));
  assert.ok(kinds.has('repairable-in-compiler'), 'no shape is repairable, which would make the lane pointless');
  assert.ok(kinds.has('routed-to-source') || kinds.has('unrouted'), 'nothing routes anywhere');
});

test('every quote a row carries is still in the file it names', () => {
  let n = 0;
  for (const r of TABLE.rows) {
    const qs = [...(r.quotes ?? [])];
    if (r.labObservation?.quote) qs.push({ source: r.labObservation.source, quote: r.labObservation.quote });
    for (const q of qs) {
      assert.ok(norm(fileText(q.source)).includes(norm(q.quote)),
        `${r.shape}/${r.candidate}: ${q.source} no longer contains "${q.quote}"`);
      n++;
    }
  }
  assert.ok(n >= 6, `only ${n} quotes checked`);
});

test('PIN-FAMILIES.md prints the ratios the table holds', () => {
  const flat = norm(MD);
  for (const r of TABLE.rows) {
    if (!measured(r)) continue;
    assert.ok(flat.includes(ratio(r.evidence.value)),
      `${r.property} / ${r.shape} / ${r.candidate}: PIN-FAMILIES.md does not print ${ratio(r.evidence.value)}`);
  }
  for (const w of STATUSES) assert.ok(flat.includes(w), `PIN-FAMILIES.md does not mention the status ${w}`);
  assert.ok(flat.includes('[SPEC]'), 'the gcc -fdisable-tree channel must stay marked [SPEC] in the prose');
});

// ---------------------------------------------------------------------------
// The counts the document makes ABOUT ITSELF.
//
// Every ratio in ../PIN-FAMILIES.md is recomputed above. Its counts of its own
// table were not, and they were the only numbers in this deliverable that no
// test could fail on -- so an adversarial read found two of them wrong: the
// prose said THREE rows route to VG-MEM-006 with appliesToThisShape "no" where
// four do, and EIGHT survive.secure-wipe rows are unmeasured where nine are.
// Both are now recomputed from the table by tableCensus(), and read back out of
// the prose here, wording and all.

const NUM_WORDS = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17,
  eighteen: 18, nineteen: 19, twenty: 20,
};
const asNumber = (s) => {
  const t = String(s).trim().toLowerCase();
  return /^\d+$/.test(t) ? Number(t) : (t in NUM_WORDS ? NUM_WORDS[t] : NaN);
};

/** One section of the MD, from its heading to the next heading of the same level or higher. */
const mdSection = (heading) => {
  const i = MD.indexOf(heading);
  assert.ok(i >= 0, `PIN-FAMILIES.md no longer has the section "${heading}"`);
  const rest = MD.slice(i + heading.length);
  const j = rest.search(new RegExp(`\n#{1,${heading.match(/^#+/)[0].length}} `));
  return heading + (j < 0 ? rest : rest.slice(0, j));
};

/** Read the numbers out of one sentence of the prose, by that sentence's own wording. */
const saysNumbers = (text, re, what) => {
  const m = text.match(re);
  assert.ok(m, `PIN-FAMILIES.md no longer states ${what} in the form this test reads: ${re}`);
  const got = m.slice(1).map(asNumber);
  assert.ok(got.every(Number.isInteger), `${what}: "${m[0]}" does not parse as numbers`);
  return got;
};

test('rowProvenance separates a recomputed row from a typed one, and the table uses all three words', () => {
  assert.equal(rowProvenance({ evidence: { tracked: true, cite: { claim: 'cell-eliminations-reversed' } } }), 'recomputed');
  assert.equal(rowProvenance({ labObservation: { what: 'a fixture loop elsewhere' } }), 'lab-run');
  assert.equal(rowProvenance({ intervention: { verdict: 'NEVER_CAME_BACK' } }), 'lab-run');
  assert.equal(rowProvenance({}), 'no-number');
  // tracked: true with no cite is recomputed by nothing, so it is not 'recomputed'
  assert.equal(rowProvenance({ evidence: { tracked: true } }), 'no-number');
  // and a row that carries both is recomputed, with the typed half counted apart
  assert.equal(rowProvenance({ evidence: { tracked: true, cite: { claim: 'x' } }, labObservation: {} }), 'recomputed');
  const c = tableCensus(TABLE);
  for (const w of PROVENANCES) assert.ok(c.provenance[w] > 0, `no row is ${w}, so the distinction is untested by the table itself`);
  assert.equal(Object.values(c.provenance).reduce((a, b) => a + b, 0), TABLE.rows.length);
});

test('PIN-FAMILIES.md counts ITS OWN rows from the table: recomputed vs typed, and drift fails here', () => {
  const c = tableCensus(TABLE);
  const prov = mdSection('## Which rows are recomputed, and which a human typed');
  const flatProv = norm(prov);

  // the provenance table's keys are the whole vocabulary, and its counts are the census
  const declared = {};
  for (const line of prov.split('\n')) {
    const m = line.match(/^\|\s*`([a-z-]+)`\s*\|\s*(\d+)\s*\|/);
    if (m) declared[m[1]] = Number(m[2]);
  }
  assert.deepEqual(Object.keys(declared).sort(), [...PROVENANCES].sort(),
    'the provenance table in PIN-FAMILIES.md does not list exactly the words rowProvenance() returns');
  assert.deepEqual(declared, c.provenance,
    `PIN-FAMILIES.md says ${JSON.stringify(declared)}, the rows say ${JSON.stringify(c.provenance)}`);

  const [rows, props, groups] = saysNumbers(flatProv,
    /That is (\d+) rows in total, over (\d+) properties and (\d+) \(property, shape\) groups/, 'the size of its own table');
  assert.deepEqual([rows, props, groups], [c.rows, c.properties, c.shapeGroups],
    `PIN-FAMILIES.md says ${rows} rows / ${props} properties / ${groups} groups; the table has ${c.rows} / ${c.properties} / ${c.shapeGroups}`);

  const [also, ofRecomputed] = saysNumbers(flatProv,
    /(\d+) of the (\d+) `recomputed` rows also carry a hand-typed `labObservation`/, 'the rows that are both');
  assert.deepEqual([also, ofRecomputed], [c.alsoLabQuote, c.provenance.recomputed],
    `PIN-FAMILIES.md says ${also} of ${ofRecomputed}; the table has ${c.alsoLabQuote} of ${c.provenance.recomputed}`);

  // a count is not enough for the rows nothing recomputes: they are the ones a
  // reader must not mistake for measurements, so each is named
  for (const label of [...c.labRun, ...c.noNumber]) {
    const [shape, candidate] = label.split(' / ');
    assert.ok(flatProv.includes(`\`${shape}\``),
      `${label} is recomputed by nothing and the provenance section does not name its shape`);
    if (candidate !== 'none') {
      assert.ok(flatProv.includes(`\`${candidate}\``),
        `${label} is recomputed by nothing and the provenance section does not name its candidate`);
    }
  }

  // the document's own copy of the wipe table must hold as many rows as the table
  // does, and as many zero counts: a row added to pin-families.json and not to the
  // prose (or the other way round) is how the two drift apart in the first place
  const wipeRows = mdSection('### `survive.secure-wipe`').split('\n').filter((l) => /^\|\s/.test(l)).slice(1);
  assert.equal(wipeRows.length, c.wipeRows,
    `the survive.secure-wipe table in PIN-FAMILIES.md prints ${wipeRows.length} rows; pin-families.json holds ${c.wipeRows}`);
  const lastCell = (l) => l.split('|').filter((x) => x.trim() !== '').pop().trim();
  const zeroCells = wipeRows.filter((l) => lastCell(l).startsWith('0 '));
  assert.equal(zeroCells.length, c.wipeUnmeasuredZeroInstance,
    `the table prints ${zeroCells.length} rows whose measured cell is a 0 count; ${c.wipeUnmeasuredZeroInstance} rows carry one`);
  const [zeroSaid] = saysNumbers(norm(MD), /(\w+) of the rows above carry a count of 0/, 'how many wipe rows carry a zero count');
  assert.equal(zeroSaid, c.wipeUnmeasuredZeroInstance,
    `PIN-FAMILIES.md says ${zeroSaid} rows carry a count of 0; ${c.wipeUnmeasuredZeroInstance} do`);

  // and the Limits section's count of the unmeasured wipe rows, which was wrong
  const [u, allWipe, zeroInstance] = saysNumbers(norm(MD),
    /(\w+) of the (\w+) `survive\.secure-wipe` rows are `unmeasured`, (\w+) of them because the corpus contains zero instances/,
    'how many wipe rows are unmeasured');
  assert.deepEqual([u, allWipe, zeroInstance], [c.wipeUnmeasured, c.wipeRows, c.wipeUnmeasuredZeroInstance],
    `PIN-FAMILIES.md says ${u} of ${allWipe} unmeasured (${zeroInstance} for zero instances); `
    + `the table has ${c.wipeUnmeasured} of ${c.wipeRows} (${c.wipeUnmeasuredZeroInstance})`);
});

test('the shapes VG-MEM-006 does not cover are both counted and NAMED in the prose', () => {
  const c = tableCensus(TABLE);
  const raw = mdSection('### Routing, and the recall that goes with it');
  const sec = norm(raw);
  const [n] = saysNumbers(sec, /(\w+) rows route to `VG-MEM-006` with `appliesToThisShape: "no"`/,
    'how many rows route to a rule whose scope does not cover their shape');
  assert.equal(n, c.routedNotApplicable,
    `PIN-FAMILIES.md says ${n} rows carry appliesToThisShape "no"; the table has ${c.routedNotApplicable}`);

  // A right count over a short list is the same defect one step further on -- and
  // the list is where the miscount came from. This section is the document's own
  // enumeration of the shapes NEITHER the pin nor the rule covers, so the bullets
  // under that sentence must be one per shape, each naming its shape id. Checking
  // only that the name appears SOMEWHERE in the section is too weak: a closing
  // paragraph mentioning the shape satisfies that while the list stays short.
  const bullets = [];
  let started = false;
  for (const line of raw.slice(raw.indexOf('rows route to `VG-MEM-006`')).split('\n')) {
    if (/^- /.test(line)) { bullets.push(line); started = true; continue; }
    if (!started) continue;
    if (/^\s+\S/.test(line)) { bullets[bullets.length - 1] += ` ${line.trim()}`; continue; }
    break; // a blank line or a new paragraph ends the list
  }
  assert.equal(bullets.length, c.routedNotApplicable,
    `the "worth reading twice" list has ${bullets.length} bullets for ${c.routedNotApplicable} rows carrying appliesToThisShape "no"`);
  for (const shape of c.routedNotApplicableShapes) {
    const hit = bullets.filter((b) => b.includes('`' + shape + '`'));
    assert.equal(hit.length, 1,
      `the list has ${hit.length} bullets naming \`${shape}\`, which routes to VG-MEM-006 with appliesToThisShape "no"; it needs exactly one`);
  }
  assert.ok(c.routedNotApplicableShapes.length >= 3, 'too few shapes here for this test to mean anything');
});

test('the unhandled counters are 0 in BOTH tracked runs, which is why those rows are unmeasured', () => {
  for (const counter of ['libcallMemset', 'memsetChk', 'nonZeroFill', 'atomicMemset', 'inlineWrapperMemset']) {
    for (const cc of ['clang-18', 'gcc-13']) {
      const got = CLAIMS['unhandled-shape-occurrences']({ rows: rowsByCc[cc], counter });
      assert.equal(got.num, 0, `${cc} ${counter}: ${got.num} occurrences now, so the row that says the corpus has none is stale`);
      assert.ok(got.den > 3000, `${cc} ${counter}: only ${got.den} records read`);
    }
  }
});

test('the claim definitions are the ones the table may cite, and each one is exercised', () => {
  const cited = new Set();
  for (const r of TABLE.rows) for (const b of [r.evidence, r.control]) if (b?.cite) cited.add(b.cite.claim);
  for (const c of cited) assert.ok(CLAIM_IDS.includes(c), `${c} is not a claim`);
  for (const c of ['cell-eliminations-reversed', 'hidden-span-eliminations-retained', 'configguard-default-equals-enabled',
    'authz-ndebug-changed-body', 'unhandled-shape-occurrences', 'plain-bzero-calls-in-corpus',
    'positive-control-present-plugin-on']) {
    assert.ok(cited.has(c), `no row cites ${c}`);
  }
});

test('the corpus really holds no plain bzero( call, and does hold the two spellings that are not it', () => {
  assert.deepEqual(recompute({ claim: 'plain-bzero-calls-in-corpus' }, DATA), { num: 0, den: 720 });
  const all = sources.map((f) => f.src).join('\n');
  assert.equal((all.match(/explicit_bzero\s*\(/g) ?? []).length, 8);
  assert.equal((all.match(/secure_bzero\s*\(/g) ?? []).length, 5);
});

test('nothing in the table carries an absolute path', () => {
  assert.deepEqual(absolutePathHits(TABLE_TEXT), []);
});

test('the validator refuses the shapes it exists to refuse', () => {
  const clone = () => JSON.parse(TABLE_TEXT);
  const withRow = (mut) => { const t = clone(); mut(t.rows.find((r) => r.status === 'measured-retained')); return t; };
  const hasProblem = (t, re) => validateTable(t).some((p) => re.test(p));

  assert.ok(hasProblem(withRow((r) => { r.evidence.tracked = false; }), /tracked === true/));
  assert.ok(hasProblem(withRow((r) => { r.evidence.value = { num: 0.5, den: 1 }; }), /integers/));
  assert.ok(hasProblem(withRow((r) => { delete r.evidence.means; }), /means/));
  assert.ok(hasProblem(withRow((r) => { r.labObservation = { what: 'x' }; }), /cannot support/));
  assert.ok(hasProblem(withRow((r) => { r.status = 'measured-somewhat'; }), /is not one of/));
  assert.ok(hasProblem(withRow((r) => { r.candidate = 'no-such-candidate'; }), /candidates\{\}/));

  const t1 = clone();
  t1.rows.find((r) => r.intervention).intervention.positionsTried = 1;
  assert.ok(hasProblem(t1, /the gate says NOT_ENOUGH_EVIDENCE/));

  const t2 = clone();
  const nr = t2.rows.find((r) => r.status === 'not-repairable-in-compiler' && r.basis === 'by-construction');
  delete nr.stage;
  assert.ok(hasProblem(t2, /must name the stage/));

  const t3 = clone();
  for (const r of t3.rows) if (r.property === 'survive.audit-record') delete r.routesTo;
  assert.ok(hasProblem(t3, /no candidate is measured to retain this shape/));

  const t4 = clone();
  t4.rows.find((r) => r.routesTo && r.routesTo.rule !== 'none').routesTo.appliesToThisShape = 'probably';
  assert.ok(hasProblem(t4, /appliesToThisShape/));

  assert.deepEqual(NOT_REPAIRABLE_BASES.filter((b) => !['measured-here', 'one-lab-run', 'by-construction'].includes(b)), []);
});

// ---------------------------------------------------------------------------
// The pipeline surgery tools/intervene.mjs performs. Pure, so it is tested here
// rather than only self-checked against whatever string the compiler prints.

test('a pipeline string round-trips, and a leaf can be taken out of it by position', () => {
  const s = 'annotation2metadata,forceattrs,function<eager-inv>(lower-expect,sroa<modify-cfg>,early-cse<>),'
    + 'cgscc(devirt<4>(inline<only-mandatory>,instcombine<max-iterations=1>,dse)),globaldce';
  const t = parsePipeline(s);
  assert.equal(renderPipeline(t), s);
  const L = leaves(t);
  assert.deepEqual(L.map((l) => l.name),
    ['annotation2metadata', 'forceattrs', 'lower-expect', 'sroa', 'early-cse', 'inline', 'instcombine', 'dse', 'globaldce']);
  assert.deepEqual(L.map((l) => l.index), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual(L[7].path, ['cgscc', 'devirt<4>']);
  assert.equal(L[3].params, '<modify-cfg>');

  // deleting by position deletes ONE occurrence, not every pass of that name
  const two = parsePipeline('f(instcombine,instcombine)');
  assert.equal(renderPipeline(withoutLeaf(two, 0)), 'f(instcombine)');
  // an adaptor left holding nothing goes with it: `f()` is not a pipeline opt accepts
  assert.equal(renderPipeline(withoutLeaf(parsePipeline('f(a),b'), 0)), 'b');
  assert.equal(renderPipeline(withoutLeaf(t, 7)), s.replace(',dse', ''));
  // and a prefix stops after the k-th leaf, keeping the nesting it was in
  assert.equal(renderPipeline(prefixLeaves(t, 0)), '');
  assert.equal(renderPipeline(prefixLeaves(t, 3)), 'annotation2metadata,forceattrs,function<eager-inv>(lower-expect)');
  assert.equal(renderPipeline(prefixLeaves(t, L.length)), s);
});

test('commas inside pass parameters are not separators', () => {
  const s = 'loop-unroll<O2;full-unroll-max=8>,simplifycfg<bonus-inst-threshold=1;no-switch-to-lookup>';
  assert.equal(renderPipeline(parsePipeline(s)), s);
  assert.equal(leaves(parsePipeline(s)).length, 2);
  const withComma = 'ipsccp,require<globals-aa>,function(scc,adce)';
  assert.equal(renderPipeline(parsePipeline(withComma)), withComma);
  assert.deepEqual(leaves(parsePipeline(withComma)).map((l) => l.name), ['ipsccp', 'require', 'scc', 'adce']);
});

test('byShape groups by (property, shape) and nothing else', () => {
  const g = byShape([
    { property: 'p', shape: 's', candidate: 'a' },
    { property: 'p', shape: 's', candidate: 'b' },
    { property: 'q', shape: 's', candidate: 'a' },
  ]);
  assert.deepEqual(Object.keys(g).sort(), ['p / s', 'q / s']);
  assert.equal(g['p / s'].length, 2);
});
