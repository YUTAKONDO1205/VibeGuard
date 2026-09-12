// The double-entry ledger: at every planned checkpoint the four accounts must
// add up to the number of properties the declaration opened, and any residue is
// booked somewhere a reader can see it.
//
// WHAT THIS IS FOR
//
//   `coverage` already carries two integers, `observed` and `planned`, and
//   VG-ART-058/059 already hold them against `states[]`. That pair catches a
//   record that miscounts what it looked at. It cannot catch a record that
//   never mentions a property at all, because `observed` is recomputed from the
//   properties the record carries and `planned` is one number with no structure
//   in it. A producer that drops a property from `properties[]` and drops the
//   same property from its own totals produces a record whose every existing
//   check passes.
//
//   Bookkeeping has had the answer to this for five hundred years: post every
//   transaction twice, against a list of accounts that was opened before the
//   transactions happened, and require the two sides to balance. A difference
//   is not rounded away and is not left implicit — it goes to an explicit
//   suspense account with a narrative attached, and the books still balance
//   with it named.
//
//   So: one CELL per (declared property, planned checkpoint). Every cell lands
//   in exactly one of four accounts —
//
//       present  + absent + unobserved + unresolved  ==  declared(checkpoint)
//
//   — and `unresolved[]` is the suspense account: "we did not look here, and
//   here is why". A cell that lands in none of the four is UNACCOUNTED, and
//   that is the finding. It is the arithmetic statement of interfaces.md §3's
//   rule that "we did not see it" and "it is not there" are different claims:
//   a record cannot lose the first by omission, because the cell still has to
//   be posted somewhere.
//
// THE DESIGN POINT, WHICH IS THE ONLY ONE THAT MATTERS
//
//   `declared` comes from the DECLARATION — a policy list, a manifest, or a
//   standalone declaration document — and never from `record.properties.length`.
//   Taken from the record's own property array the identity holds by
//   construction for every record ever written, and the check is theatre. The
//   fixture `testdata/records/v1-observed-only.json` exists to prove this one
//   is not: it lists four declared properties and carries states for two, and
//   it must fail. If a future edit makes it pass, the check has been gutted.
//
//   The planned checkpoint list comes from the same place, for the same reason.
//   Derived from the checkpoints that appear in `states[]` it would say that
//   every run planned exactly what it managed to do.
//
// WHAT THIS DOES NOT CATCH, STATED HERE RATHER THAN DISCOVERED LATER
//
//   When the declaration is read out of the record itself — which is what
//   happens with no `--declared` document and no `declares` block in the
//   manifest — a producer that shrinks `properties[]` AND shrinks
//   `declaredProperties` by the same property emits a record that balances.
//   That is the same limit the bundle digests have: nothing here binds a record
//   to an authority outside it. The fixture
//   `testdata/records/v1-shrunk-declaration.json` is that record, and its test
//   asserts it exits 0 unaided and exits 2 the moment an outside declaration is
//   named. The second book is what closes it, and the second book has to come
//   from outside the record.
//
//   The same limit runs along the checkpoint axis: a record that narrows
//   `ledger.plannedCheckpoints` AND drops the states at the checkpoint it
//   dropped balances over what is left. Keeping the states is caught —
//   `postLedger` returns those cells as `offPlan` and `verify.mjs` reports
//   `VG-ART-068` — so what is left is the same disclosed limit as above with
//   `plannedCheckpoints` in place of `declaredProperties`, and it is closed by
//   the same outside declaration.
//
//   What is NOT a limit, though it was: a property whose own
//   `plannedCheckpoints` is `[]`. It passed the widening check vacuously,
//   matched no checkpoint, opened no account and posted nowhere, while
//   `declaredProperties` went on counting it — the denominator and the columns
//   came apart and the denominator was the half that kept being printed. It is
//   a `DeclarationError` now, so the ledger is UNCHECKED rather than balanced
//   over whatever is left; see `readDeclaration`.
//
// This module does the arithmetic and returns data. The findings vocabulary
// lives in verify.mjs with every other finding this component emits; splitting
// it would put two files in the business of wording the same complaint.

/** The four accounts, in the order the identity is written above. */
export const ACCOUNTS = Object.freeze(['present', 'absent', 'unobserved', 'unresolved']);

/**
 * The coarse observation verdict evidence-v0 records carry, and the account
 * each one posts to. `UNOBSERVED` is interfaces.md §3's `NOT_OBSERVED` under
 * the record's own name for it; it posts to its own account and never to
 * `absent`, which is the whole reason both columns exist.
 */
export const VERDICT_ACCOUNT = Object.freeze({
  PRESENT: 'present',
  ABSENT: 'absent',
  UNOBSERVED: 'unobserved',
});

/** The record schema version that carries a ledger. `evidence-v0` does not. */
export const LEDGER_SCHEMA_VERSION = 'evidence-v1';

/** A standalone declaration document, for `--declared`. */
export const DECLARATION_SCHEMA_VERSION = 'evidence-declaration-v1';

/** A declaration that cannot be read is a check that cannot be completed. */
export class DeclarationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeclarationError';
  }
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function duplicatesOf(list) {
  const seen = new Set();
  const dup = new Set();
  for (const x of list) {
    if (seen.has(x)) dup.add(x);
    seen.add(x);
  }
  return [...dup].sort();
}

/**
 * Read a declaration from whatever shape carries one, and refuse the shapes
 * that cannot be counted.
 *
 * A declaration is the list of accounts, opened before the run: which property
 * ids the policy declared, and which checkpoints it planned to observe them at.
 * A property may narrow its own list to a subset of the planned checkpoints; it
 * may not widen it, because a checkpoint nobody planned is not one this ledger
 * can hold anything against, and it may not narrow it to NOTHING, because a
 * property planned at no checkpoint opens no account, posts to no column, and
 * leaves the books balancing by subtraction while `declaredProperties` still
 * counts it.
 *
 * @param {unknown} value
 * @param {string} source  where it came from, for the report
 * @returns {{source: string, plannedCheckpoints: string[], properties: Array<{propertyId: string, plannedCheckpoints: string[]}>}}
 */
export function readDeclaration(value, source) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeclarationError(`the ${source} declaration is not a JSON object`);
  }
  // A standalone document says what it is. The `declares` block in a manifest
  // and the pair of fields read out of a record carry no version of their own
  // and are not asked for one, so the check is on the value when it is there
  // rather than on its presence: a file that says it is something else is
  // refused rather than duck-typed into service.
  if (value.schemaVersion !== undefined && value.schemaVersion !== DECLARATION_SCHEMA_VERSION) {
    throw new DeclarationError(
      `the ${source} declaration says schemaVersion ${JSON.stringify(value.schemaVersion)}; this ` +
        `reads ${DECLARATION_SCHEMA_VERSION}, and a document of another shape that happens to carry ` +
        'the right two keys is not one to count against',
    );
  }
  const planned = value.plannedCheckpoints;
  if (!Array.isArray(planned) || planned.length === 0 || !planned.every(isNonEmptyString)) {
    throw new DeclarationError(
      `the ${source} declaration has no usable plannedCheckpoints; it must be a non-empty array of ` +
        'checkpoint names, and it comes from the plan rather than from what ran',
    );
  }
  const dupCheckpoints = duplicatesOf(planned);
  if (dupCheckpoints.length > 0) {
    throw new DeclarationError(
      `the ${source} declaration names ${JSON.stringify(dupCheckpoints)} twice in plannedCheckpoints; ` +
        'a checkpoint listed twice would double every denominator that uses it',
    );
  }

  const props = value.properties;
  if (!Array.isArray(props) || props.length === 0) {
    throw new DeclarationError(
      `the ${source} declaration lists no properties; a ledger with no accounts balances for every ` +
        'record and says nothing about any of them',
    );
  }
  const out = [];
  for (let i = 0; i < props.length; i += 1) {
    const p = props[i];
    const id = p && typeof p === 'object' && !Array.isArray(p) ? p.propertyId : undefined;
    if (!isNonEmptyString(id)) {
      throw new DeclarationError(
        `the ${source} declaration's property ${i} has no propertyId; an account with no name cannot ` +
          'be posted to',
      );
    }
    let own = planned;
    if (p.plannedCheckpoints !== undefined) {
      if (!Array.isArray(p.plannedCheckpoints) || !p.plannedCheckpoints.every(isNonEmptyString)) {
        throw new DeclarationError(`${id}: plannedCheckpoints is not an array of checkpoint names`);
      }
      // An empty list is the quiet way to delete a property from the ledger
      // while leaving it in `declaredProperties`: it matches no checkpoint, so
      // `declared` never counts it and no cell is ever posted for it, and the
      // report still says the record declared it. That is the same defeat as
      // taking the denominator from `properties.length`, one key further in.
      if (p.plannedCheckpoints.length === 0) {
        throw new DeclarationError(
          `${id} plans no checkpoints at all; a property whose plannedCheckpoints is empty opens no ` +
            'account at any checkpoint, so it would drop out of every column while still being counted ' +
            'as a declared property. A property planned nowhere is not a declared property: remove it ' +
            'from the declaration, or name the checkpoints it is planned at',
        );
      }
      const widened = p.plannedCheckpoints.filter((c) => !planned.includes(c));
      if (widened.length > 0) {
        throw new DeclarationError(
          `${id} plans ${JSON.stringify(widened)}, which the ${source} declaration does not plan at all; ` +
            'a property may narrow the planned list, never widen it',
        );
      }
      own = [...p.plannedCheckpoints];
    }
    out.push({ propertyId: id, plannedCheckpoints: own });
  }
  const dupProps = duplicatesOf(out.map((p) => p.propertyId));
  if (dupProps.length > 0) {
    throw new DeclarationError(
      `the ${source} declaration names ${JSON.stringify(dupProps)} twice; a property declared twice ` +
        'inflates the denominator it is counted against',
    );
  }
  return { source, plannedCheckpoints: [...planned], properties: out };
}

/**
 * Resolve which declaration to hold the record against.
 *
 * Precedence, strongest first. It is an ordering of how much the record's own
 * author controls the document:
 *
 *   'external' — a declaration document named on the command line. The only
 *                one the record's producer did not write, and therefore the
 *                only one that can catch a record which shrank both books.
 *   'manifest' — a `declares` block in the bundle's manifest.json. A second
 *                file, written by the bundler rather than by the record; weaker
 *                than external, stronger than nothing.
 *   'record'    — `declaredProperties` and `ledger.plannedCheckpoints` in the
 *                record. Still not `properties.length`, so it catches a record
 *                that dropped a property from one book; it cannot catch one
 *                that dropped it from both.
 *
 * @param {Record<string, unknown>} record
 * @param {{declared?: unknown, manifest?: Record<string, unknown>|null}} [opts]
 * @returns {{declaration: object|null, error: string|null}}
 */
export function resolveDeclaration(record, opts = {}) {
  let value;
  let source;
  if (opts.declared !== undefined && opts.declared !== null) {
    value = opts.declared;
    source = 'external';
  } else if (opts.manifest && opts.manifest.declares !== undefined) {
    value = opts.manifest.declares;
    source = 'manifest';
  } else {
    value = {
      plannedCheckpoints: record?.ledger?.plannedCheckpoints,
      properties: record?.declaredProperties,
    };
    source = 'record';
  }
  try {
    return { declaration: readDeclaration(value, source), error: null };
  } catch (e) {
    if (e instanceof DeclarationError) return { declaration: null, error: e.message };
    throw e;
  }
}

/** The record's own declaration, for the cross-check. Null when it has none. */
export function recordDeclaration(record) {
  try {
    return readDeclaration(
      {
        plannedCheckpoints: record?.ledger?.plannedCheckpoints,
        properties: record?.declaredProperties,
      },
      'record',
    );
  } catch {
    return null;
  }
}

/**
 * Does this `unresolved[]` entry settle this cell?
 *
 * An entry names one checkpoint with `checkpoint`, or several with
 * `checkpoints`. An entry that names neither settles nothing — deliberately.
 * A blanket "this property is unresolved" would let one line settle every cell
 * a run skipped, which is the suspense account swallowing the ledger instead of
 * exposing it.
 */
export function unresolvedCovers(entry, propertyId, checkpoint) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return false;
  if (entry.propertyId !== propertyId) return false;
  if (typeof entry.checkpoint === 'string') return entry.checkpoint === checkpoint;
  if (Array.isArray(entry.checkpoints)) return entry.checkpoints.includes(checkpoint);
  return false;
}

/**
 * Post every planned cell, and add the columns up.
 *
 * @param {Record<string, unknown>} record
 * @param {{plannedCheckpoints: string[], properties: Array<{propertyId: string, plannedCheckpoints: string[]}>}} declaration
 * @returns {{
 *   entries: Array<{checkpoint: string, declared: number, present: number, absent: number, unobserved: number, unresolved: number, unaccounted: number}>,
 *   cells: Array<{propertyId: string, checkpoint: string, account: string, reason: string|null}>,
 *   unaccounted: Array<{propertyId: string, checkpoint: string, reason: string}>,
 *   undeclared: string[],
 *   offPlan: Array<{propertyId: string, checkpoint: string}>,
 *   declaredPropertyCount: number,
 * }}
 */
export function postLedger(record, declaration) {
  const props = Array.isArray(record?.properties) ? record.properties : [];
  const unresolvedList = Array.isArray(record?.unresolved) ? record.unresolved : [];

  const statesOf = new Map();
  for (const pr of props) {
    if (pr === null || typeof pr !== 'object') continue;
    const id = pr.propertyId;
    if (!isNonEmptyString(id)) continue;
    const states = Array.isArray(pr.states) ? pr.states : [];
    // A property carried twice would post its cells twice. Keep the first and
    // let the second show up as a duplicate rather than silently merging them.
    if (!statesOf.has(id)) statesOf.set(id, states);
    else statesOf.set(id, null);
  }

  const entries = [];
  const cells = [];
  const unaccounted = [];

  for (const checkpoint of declaration.plannedCheckpoints) {
    const tally = { present: 0, absent: 0, unobserved: 0, unresolved: 0, unaccounted: 0 };
    let declared = 0;
    for (const p of declaration.properties) {
      if (!p.plannedCheckpoints.includes(checkpoint)) continue;
      declared += 1;
      const { account, reason } = postCell(p.propertyId, checkpoint, statesOf, unresolvedList);
      tally[account] += 1;
      cells.push({ propertyId: p.propertyId, checkpoint, account, reason });
      if (account === 'unaccounted') unaccounted.push({ propertyId: p.propertyId, checkpoint, reason });
    }
    entries.push({ checkpoint, declared, ...tally });
  }

  const declaredIds = new Set(declaration.properties.map((p) => p.propertyId));
  const undeclared = [...statesOf.keys()].filter((id) => !declaredIds.has(id)).sort();

  // The other end of `undeclared`, along the checkpoint axis instead of the
  // property axis: a state the record carries at a checkpoint the declaration
  // does not plan FOR THAT PROPERTY. It is posted to no column — `declared`
  // never counted it, so its absence cannot show up as an imbalance — and
  // without naming it here, narrowing `plannedCheckpoints` (top level, or one
  // property's own) quietly removes a whole column from the check while the
  // report goes on printing a balanced ledger.
  const plannedFor = new Map(declaration.properties.map((p) => [p.propertyId, new Set(p.plannedCheckpoints)]));
  const offPlanSeen = new Set();
  const offPlan = [];
  for (const [id, states] of statesOf) {
    const plan = plannedFor.get(id);
    // An undeclared property is already named by `undeclared`, and a property
    // carried twice already has an unaccounted cell; neither is reported twice.
    if (plan === undefined || states === null) continue;
    for (const s of states) {
      if (s === null || typeof s !== 'object') continue;
      if (!isNonEmptyString(s.checkpoint) || plan.has(s.checkpoint)) continue;
      const key = `${id}\u0000${s.checkpoint}`;
      if (offPlanSeen.has(key)) continue;
      offPlanSeen.add(key);
      offPlan.push({ propertyId: id, checkpoint: s.checkpoint });
    }
  }
  offPlan.sort((a, b) => a.propertyId.localeCompare(b.propertyId) || a.checkpoint.localeCompare(b.checkpoint));

  return {
    entries,
    cells,
    unaccounted,
    undeclared,
    offPlan,
    declaredPropertyCount: declaration.properties.length,
  };
}

/** Which account one cell posts to, and why when the answer is "none of them". */
function postCell(propertyId, checkpoint, statesOf, unresolvedList) {
  if (!statesOf.has(propertyId)) {
    const settled = unresolvedList.some((e) => unresolvedCovers(e, propertyId, checkpoint));
    return settled
      ? { account: 'unresolved', reason: null }
      : {
          account: 'unaccounted',
          reason:
            'the record carries no states for this property and no unresolved[] entry names this ' +
            'cell, so nothing in the record says whether it was looked at',
        };
  }
  const states = statesOf.get(propertyId);
  if (states === null) {
    return {
      account: 'unaccounted',
      reason: 'the record carries this propertyId more than once, so the cell has more than one posting',
    };
  }
  const at = states.filter((s) => s !== null && typeof s === 'object' && s.checkpoint === checkpoint);
  if (at.length === 0) {
    const settled = unresolvedList.some((e) => unresolvedCovers(e, propertyId, checkpoint));
    return settled
      ? { account: 'unresolved', reason: null }
      : {
          account: 'unaccounted',
          reason:
            'the property has states but none at this checkpoint, and no unresolved[] entry names ' +
            'this cell. A checkpoint that was planned and then not mentioned is exactly the omission ' +
            'this ledger exists to catch',
        };
  }
  if (at.length > 1) {
    return {
      account: 'unaccounted',
      reason: `${at.length} states carry this checkpoint; a cell posts once, and which of them is the ` +
        'posting is not a question the record answers',
    };
  }
  const verdict = at[0].verdict;
  const account = Object.prototype.hasOwnProperty.call(VERDICT_ACCOUNT, verdict)
    ? VERDICT_ACCOUNT[verdict]
    : null;
  if (account === null) {
    return {
      account: 'unaccounted',
      reason: `the state's verdict is ${JSON.stringify(verdict ?? null)}, which is not one of PRESENT, ` +
        'ABSENT or UNOBSERVED, so there is no account to post it to',
    };
  }
  return { account, reason: null };
}

/**
 * Compare the record's own ledger block against the recomputed one.
 *
 * The record may carry its tally for a reader's benefit; this component never
 * takes a count from it. A disagreement is its own complaint, separate from an
 * imbalance, because the two say different things: an imbalance says the run
 * lost track of a cell, a disagreement says the record's summary and the
 * record's detail were produced by two different pieces of arithmetic.
 *
 * `comparable` is false when there is nothing to compare against. That is not a
 * disagreement and must not be reported as one — it is a field nobody could
 * check, which is exit 3's business rather than a finding's.
 *
 * `uncompared` carries the same distinction one level down, and it exists
 * because the first version of this function did not have it. A number that the
 * entry does not carry is a number nobody compared, and skipping it silently
 * inverted the incentive: `entries` written out as
 * `[{"checkpoint":"ir-pre"},{"checkpoint":"ir-post"}]` — the planned names and
 * not one count — compared nothing at all and still landed `ledger.entries` on
 * CHECKED, while omitting the `entries` key honestly cost exit 3. A producer
 * could buy VERIFIED_CLEAN by writing LESS. So an entry of a v1 ledger carries
 * `declared` and all four accounts; every one it leaves out goes on
 * `uncompared`, the caller puts `ledger.entries` on UNCHECKED, and the shell is
 * then worth exactly what the honest omission is worth and never more.
 *
 * @returns {{comparable: boolean, problems: string[], uncompared: string[]}}
 */
export function compareWrittenLedger(record, posted) {
  const written = record?.ledger?.entries;
  if (!Array.isArray(written)) {
    return { comparable: false, problems: [], uncompared: [] };
  }
  const out = [];
  const nobodyCompared = [];
  const byCheckpoint = new Map();
  for (const e of written) {
    if (e === null || typeof e !== 'object' || !isNonEmptyString(e.checkpoint)) {
      out.push(`a ledger entry has no checkpoint: ${JSON.stringify(e)}`);
      continue;
    }
    if (byCheckpoint.has(e.checkpoint)) {
      out.push(`the ledger carries two entries for ${JSON.stringify(e.checkpoint)}`);
      continue;
    }
    byCheckpoint.set(e.checkpoint, e);
  }
  for (const got of posted.entries) {
    const said = byCheckpoint.get(got.checkpoint);
    if (said === undefined) {
      out.push(`the ledger has no entry for the planned checkpoint ${JSON.stringify(got.checkpoint)}`);
      continue;
    }
    byCheckpoint.delete(got.checkpoint);
    for (const account of ACCOUNTS) {
      if (said[account] === undefined) {
        nobodyCompared.push(`${got.checkpoint}.${account}`);
      } else if (said[account] !== got[account]) {
        out.push(
          `${got.checkpoint}: the ledger says ${account}=${JSON.stringify(said[account])}, the ` +
            `recomputation gives ${got[account]}`,
        );
      }
    }
    if (said.declared === undefined) {
      nobodyCompared.push(`${got.checkpoint}.declared`);
    } else if (said.declared !== got.declared) {
      out.push(
        `${got.checkpoint}: the ledger says declared=${JSON.stringify(said.declared)}, the declaration ` +
          `opens ${got.declared} account(s) here`,
      );
    }
  }
  for (const left of byCheckpoint.keys()) {
    out.push(`the ledger carries an entry for ${JSON.stringify(left)}, which is not a planned checkpoint`);
  }
  return { comparable: true, problems: out, uncompared: nobodyCompared };
}

/**
 * Compare the declaration actually used against the record's own, when they are
 * two different documents. Same shape of complaint as above and for the same
 * reason: two books that disagree about which accounts exist is a fact about
 * the pair, not about either one.
 *
 * @returns {{comparable: boolean, problems: string[]}}
 */
export function compareDeclarations(used, own) {
  if (own === null) return { comparable: false, problems: [] };
  const out = [];
  const usedIds = new Set(used.properties.map((p) => p.propertyId));
  const ownIds = new Set(own.properties.map((p) => p.propertyId));
  const missing = [...usedIds].filter((id) => !ownIds.has(id)).sort();
  const extra = [...ownIds].filter((id) => !usedIds.has(id)).sort();
  if (missing.length > 0) {
    out.push(`the record does not declare ${JSON.stringify(missing)}, which the ${used.source} declaration does`);
  }
  if (extra.length > 0) {
    out.push(`the record declares ${JSON.stringify(extra)}, which the ${used.source} declaration does not`);
  }
  const cpMissing = used.plannedCheckpoints.filter((c) => !own.plannedCheckpoints.includes(c));
  const cpExtra = own.plannedCheckpoints.filter((c) => !used.plannedCheckpoints.includes(c));
  if (cpMissing.length > 0) {
    out.push(`the record does not plan ${JSON.stringify(cpMissing)}, which the ${used.source} declaration plans`);
  }
  if (cpExtra.length > 0) {
    out.push(`the record plans ${JSON.stringify(cpExtra)}, which the ${used.source} declaration does not`);
  }
  return { comparable: true, problems: out };
}

/**
 * The whole check, as data. `verify.mjs` turns this into findings.
 *
 * @param {Record<string, unknown>} record
 * @param {{declared?: unknown, manifest?: Record<string, unknown>|null}} [opts]
 * @returns {{
 *   checkable: boolean,
 *   why: string|null,
 *   source: string|null,
 *   posted: object|null,
 *   imbalances: Array<{checkpoint: string, declared: number, posted: number, cells: Array<{propertyId: string, reason: string}>}>,
 *   writtenLedger: {comparable: boolean, problems: string[]},
 *   declarations: {comparable: boolean, problems: string[]},
 *   undeclared: string[],
 * }}
 */
export function auditLedger(record, opts = {}) {
  const blank = {
    checkable: false,
    why: null,
    source: null,
    posted: null,
    imbalances: [],
    writtenLedger: { comparable: false, problems: [], uncompared: [] },
    declarations: { comparable: false, problems: [] },
    undeclared: [],
  };

  const ledger = record?.ledger;
  const hasLedgerBlock = ledger !== null && typeof ledger === 'object' && !Array.isArray(ledger);
  const external = opts.declared !== undefined && opts.declared !== null;
  const fromManifest = Boolean(opts.manifest && opts.manifest.declares !== undefined);
  if (!hasLedgerBlock && !external && !fromManifest) {
    // Not a finding. Nothing was checked, and saying so is the point: exit 3,
    // never 0. A record that declares itself evidence-v1 and carries no ledger
    // is a record whose central claim nobody could look at.
    return {
      ...blank,
      why:
        'the record declares evidence-v1 and carries no usable ledger block, so neither the planned ' +
        'checkpoints nor its own tally could be read',
    };
  }

  const { declaration, error } = resolveDeclaration(record, opts);
  if (declaration === null) return { ...blank, why: error };

  const posted = postLedger(record, declaration);
  const imbalances = [];
  for (const e of posted.entries) {
    const sum = ACCOUNTS.reduce((n, a) => n + e[a], 0);
    if (sum !== e.declared) {
      imbalances.push({
        checkpoint: e.checkpoint,
        declared: e.declared,
        posted: sum,
        cells: posted.unaccounted
          .filter((u) => u.checkpoint === e.checkpoint)
          .map((u) => ({ propertyId: u.propertyId, reason: u.reason })),
      });
    }
  }

  // The record's own tally is compared, never consulted. When it is absent the
  // comparison is UNCHECKED rather than clean; `comparable` is what carries
  // that distinction out of here.
  const writtenLedger = hasLedgerBlock
    ? compareWrittenLedger(record, posted)
    : { comparable: false, problems: [], uncompared: [] };

  // Two declarations only exist to be compared when the one in force came from
  // outside the record. When it came from the record there is one book, and
  // comparing it with itself would report agreement that means nothing.
  const declarations =
    declaration.source === 'record'
      ? { comparable: false, problems: [] }
      : compareDeclarations(declaration, recordDeclaration(record));

  return {
    checkable: true,
    why: null,
    source: declaration.source,
    posted,
    imbalances,
    writtenLedger,
    declarations,
    undeclared: posted.undeclared,
  };
}
