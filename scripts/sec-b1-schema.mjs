// B1 — the single source of truth for the pair record shape, shared by the
// generator (sec-b1-gen-corpus.mjs) and the evaluator (sec-b1-er-eval.mjs).
//
// Why this module exists: the first cut of the harness had the generator WRITE
// `outcomeTransformedFalse` while the evaluator READ `results.transformedFalse`.
// `undefined === 'relocated'` is `false`, so the mismatch was invisible — it
// silently degraded to a fallback path instead of throwing. Four fields failed
// this way. The lesson is that a missing key must be a THROW, never a falsy
// value that reads like a legitimate "no". Everything below is built around
// that: `req()` is fail-closed, `census()` proves every pair is accounted for,
// and `assertVaries()` flags a field that never changes (the shared symptom of
// a dead read: detectedOrigTrue was hardcoded true, gateWarnings stuck at 0).
//
// Pure functions only. No fs, no Date.now, no Math.random.

/**
 * Canonical pair field names. Both scripts import these instead of typing the
 * string literally, so a rename is a one-line change that breaks loudly on the
 * other side rather than a silent degrade.
 */
export const F = {
  transformId: 'transformId',
  transformName: 'transformName',
  category: 'category',
  d2Predicted: 'd2Predicted',
  adversarialCost: 'adversarialCost',
  ruleId: 'ruleId',
  severity: 'severity',
  language: 'language',
  origPath: 'origPath',
  transformedPath: 'transformedPath',
  payloadExecutable: 'payloadExecutable',
  needsManualReview: 'needsManualReview',
  // existence observations (thresholds ignored — SCOPE §2.3 `detect`)
  detectedOrigFalse: 'detectedOrigFalse',
  detectedOrigTrue: 'detectedOrigTrue',
  detectedTransformedFalse: 'detectedTransformedFalse',
  detectedTransformedTrue: 'detectedTransformedTrue',
  // gate observations (severity/confidence threshold passed)
  gatePassedOrigFalse: 'gatePassedOrigFalse',
  gatePassedOrigTrue: 'gatePassedOrigTrue',
  gatePassedTransformedFalse: 'gatePassedTransformedFalse',
  gatePassedTransformedTrue: 'gatePassedTransformedTrue',
  // three-valued landing verdict, authoritative over the booleans
  outcomeTransformedFalse: 'outcomeTransformedFalse',
  outcomeTransformedTrue: 'outcomeTransformedTrue',
};

/** The keys every usable pair MUST carry. Missing any one is a hard error. */
export const REQUIRED_PAIR_KEYS = [
  F.transformId, F.category, F.ruleId, F.payloadExecutable,
  F.detectedOrigFalse, F.detectedOrigTrue,
  F.detectedTransformedFalse, F.detectedTransformedTrue,
  F.gatePassedOrigFalse, F.gatePassedOrigTrue,
  F.gatePassedTransformedFalse, F.gatePassedTransformedTrue,
  F.outcomeTransformedFalse, F.outcomeTransformedTrue,
  F.needsManualReview,
];

const LANDINGS = new Set(['detected', 'absent', 'relocated']);

/**
 * Fail-closed accessor. A missing key throws instead of yielding `undefined`,
 * which is the whole point: the dead reads this module exists to prevent all
 * looked like `obj.absentKey` quietly returning a falsy value.
 */
export function req(obj, key) {
  if (obj == null || !Object.prototype.hasOwnProperty.call(obj, key)) {
    throw new Error(`sec-b1-schema: required field \`${key}\` missing on ${obj?.pairId ?? '<pair>'}`);
  }
  return obj[key];
}

/** Boolean observation, fail-closed on a non-boolean. */
export function reqBool(pair, key) {
  const v = req(pair, key);
  if (typeof v !== 'boolean') {
    throw new Error(`sec-b1-schema: \`${key}\` must be boolean, got ${JSON.stringify(v)} on ${pair?.pairId ?? '<pair>'}`);
  }
  return v;
}

/** Three-valued landing for the transformed side of one arm. Fail-closed. */
export function landing(pair, arm) {
  const key = arm === 'false' ? F.outcomeTransformedFalse : F.outcomeTransformedTrue;
  const v = req(pair, key);
  if (!LANDINGS.has(v)) {
    throw new Error(`sec-b1-schema: \`${key}\` must be detected|absent|relocated, got ${JSON.stringify(v)} on ${pair?.pairId ?? '<pair>'}`);
  }
  return v;
}

/**
 * Per-arm relocation. Uses the arm-specific landing, NOT the arm-agnostic
 * `needsManualReview` flag — a pair relocated in only one arm must leave the
 * denominator of THAT arm alone, not both. (The old code OR-ed in the shared
 * flag, so 14 asymmetrically-relocated pairs were dropped from both arms.)
 */
export function relocatedInArm(pair, arm) {
  return landing(pair, arm) === 'relocated';
}

/** True when this pair is the fix-real negative control (payload removed). */
export function isNegativeControl(pair) {
  return req(pair, F.payloadExecutable) === false;
}

/**
 * Conservation law: every pair lands in EXACTLY one bucket for a given arm, and
 * the buckets sum to the total. If the generator wrote 100 relocated pairs and
 * the evaluator sees 0, this throws — the mismatch that used to be silent.
 *
 * Buckets (per arm): notInDenominator (original undetected), evaded
 * (detected→gone), survived (detected→still detected), relocated (ambiguous).
 */
export function census(pairs, arm, kind = 'exists') {
  const oKey = kind === 'gate'
    ? (arm === 'false' ? F.gatePassedOrigFalse : F.gatePassedOrigTrue)
    : (arm === 'false' ? F.detectedOrigFalse : F.detectedOrigTrue);
  const tKey = kind === 'gate'
    ? (arm === 'false' ? F.gatePassedTransformedFalse : F.gatePassedTransformedTrue)
    : (arm === 'false' ? F.detectedTransformedFalse : F.detectedTransformedTrue);

  const b = { notInDenominator: 0, evaded: 0, survived: 0, relocated: 0 };
  for (const p of pairs) {
    if (relocatedInArm(p, arm)) { b.relocated += 1; continue; }
    if (reqBool(p, oKey) !== true) { b.notInDenominator += 1; continue; }
    if (reqBool(p, tKey) === false) b.evaded += 1;
    else b.survived += 1;
  }
  const sum = b.notInDenominator + b.evaded + b.survived + b.relocated;
  if (sum !== pairs.length) {
    throw new Error(`sec-b1-schema: census does not conserve (${sum} != ${pairs.length}) for arm=${arm} kind=${kind}`);
  }
  return b;
}

/**
 * Flags a field that takes only ONE value across every pair. A dead read shows
 * up here: detectedOrigTrue hardcoded true (404/404), gateWarnings stuck at 0.
 * Returns { field, distinctValues, constant } — the caller decides if a
 * constant is legitimate (some fields genuinely never vary) or a bug.
 */
export function assertVaries(pairs, key) {
  const seen = new Set();
  for (const p of pairs) seen.add(JSON.stringify(p?.[key]));
  return { field: key, distinctValues: seen.size, constant: seen.size <= 1, sample: [...seen].slice(0, 3) };
}

/** Throws on the first pair missing a required key. Call once before scoring. */
export function validatePairs(pairs) {
  for (const p of pairs) {
    for (const k of REQUIRED_PAIR_KEYS) req(p, k);
    landing(p, 'false');
    landing(p, 'true');
  }
  return pairs.length;
}
