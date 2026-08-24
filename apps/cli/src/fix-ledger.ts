// A fixer's claims, written down so they outlive the finding they came from.
//
// ── THE PROBLEM THIS EXISTS FOR ─────────────────────────────────────────────
//
// `--fix --write` inserts a protection and says so. That statement is about the
// SOURCE, and the whole subject of this ledger is that the source is not what
// ships — so the claim is born NOT_OBSERVED and only an observation of the
// build output may move it. The trouble is that there is nothing left to
// observe it FROM. The moment the fix lands, the finding it repaired is gone,
// so a later `claimsFromFindings` has nothing to rebuild the claim out of. The
// claim did not stay unproven; it disappeared, and whether the inserted
// protection survived the build was then checked by nothing, ever.
//
// The CLI said so, in as many words, rather than printing an unavailable
// verification. This file is what makes the sentence unnecessary.
//
// ── WHAT IS NOT BUILT, AND WHY IT CANNOT BE ─────────────────────────────────
//
// The obvious design is to fix, build, and settle in one run. It is not
// possible and the reason is structural, not effort: at fix time the build
// output on disk is the PRE-EDIT build, so the inserted line is in no
// `sourcesContent` anywhere and jurisdiction is empty by construction. Every
// claim would resolve NOT_OBSERVED and the run would look like it had checked
// something. Closing that gap needs the user's build to run BETWEEN the two
// halves, which would mean this CLI executing an arbitrary build command — and
// `index.ts` carries a standing refusal to run any tool at all, because a
// zero-egress product that grows a subprocess runner has stopped being one.
//
// So: the fixer writes down what it did, and the NEXT run — after the user has
// rebuilt — settles it. The wait is real and is stated in the output.
//
// ── THE BINDING IS THE LINE, NOT THE FILE ───────────────────────────────────
//
// An entry is usable only while the text it says it inserted is still in the
// source. Not a whole-file hash: that would kill the claim the moment the user
// edited anything else in the same file, which is most edits, and a ledger that
// expires on unrelated work is a ledger nobody keeps. The line is the smallest
// thing that is actually the subject of the claim — it survives edits elsewhere
// and dies when the repair is reverted, which is exactly the discrimination
// wanted.
//
// An entry that settled PRESENT is KEPT rather than retired. Watching a
// protection that survived one build disappear from the next is the reason to
// have a ledger at all; pruning on success would throw away the only thing it
// is uniquely able to see.
//
// ── HOW FAR THIS FILE MAY BE TRUSTED ────────────────────────────────────────
//
// ★ This is the first UNTRUSTED, on-disk input that can reach `crossExamine` as
// a claim. Everything upstream of it is a pure function in this repository. A
// ledger is a file in the user's tree, and anyone who can write it can, by
// matching `insertedLine` and `witness` to text that really is in the build,
// manufacture a settled `PRESENT` line for a subject nobody ever inserted.
//
// Validation here refuses malformed and degenerate entries — wrong types, short
// probes, short witnesses, paths that climb out of the target, a file bigger
// than a ledger has any reason to be. None of that refuses a well-formed lie,
// and no amount of validation could. The honest statement of its trust level is
// that it is exactly that of the source tree being scanned: whoever can write
// this file can also write the source the scanner reads. It is not a channel
// for one party to hand another party's scanner a conclusion.
//
// ── WHY NOTHING HERE IMPORTS THE OBSERVER ───────────────────────────────────
//
// `apps/cli/build.mjs` requires `@vibeguard/artifact-integrity/bundle` and
// `/cross-examine` to stay behind dynamic imports, and `assertLazyBoundaries()`
// FAILS THE BUILD if esbuild hoists either into startup. A static import from
// this module — which `index.ts` loads unconditionally — would do exactly that.
// So this file knows about claims and files, and nothing about adjudication.

import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import type { ProtectionClaim } from '@vibeguard/findings-schema';

/** Directory and file the ledger lives in, relative to the scanned root. */
const LEDGER_DIR = '.vibeguard';
const LEDGER_FILE = 'fix-ledger.json';

/**
 * Entries kept, and entries read.
 *
 * Enforced on BOTH sides on purpose. Capping only the write would leave a
 * hand-written ledger free to be enormous, and the read path opens every
 * entry's source file — so an uncapped read is a way to make a scan walk an
 * arbitrary file list. The cap is generous against real use: a `--fix --write`
 * over a large tree inserts tens of protections, not hundreds.
 */
const MAX_ENTRIES = 200;

/**
 * Largest ledger this will parse.
 *
 * `MAX_ENTRIES` bounds what is USED; this bounds what is READ into memory,
 * which is a different question and the one that matters before `JSON.parse`
 * has run. 200 entries of a long inserted line and a path is far under a
 * megabyte.
 */
const MAX_LEDGER_BYTES = 1024 * 1024;

/**
 * Shortest inserted line worth recording.
 *
 * Deliberately the same 20 characters `crossExamine` requires of a
 * `sourceProbe`, because that is what this becomes. Recording a shorter one
 * would write an entry that can only ever come back NOT_OBSERVED — a row that
 * costs a reader attention and can never resolve.
 */
const MIN_INSERTED_CHARS = 20;

/** Shortest witness, matching the adjudicator's own floor. */
const MIN_WITNESS_CHARS = 4;

export interface FixLedgerEntry {
  ruleId: string;
  title: string;
  safety: string;
  /** Relative to the scanned root, forward slashes. */
  filePath: string;
  startLine: number;
  insertedLine: string;
  witness?: string;
  createdAt: string;
}

/** The scanned root — the directory a relative `filePath` is resolved against. */
export function ledgerRoot(target: string, targetIsFile: boolean): string {
  return targetIsFile ? dirname(resolve(target)) : resolve(target);
}

export function ledgerPath(target: string, targetIsFile: boolean): string {
  return join(ledgerRoot(target, targetIsFile), LEDGER_DIR, LEDGER_FILE);
}

/** LF, so a ledger written on Windows and read on Linux compares equal. */
function normalise(s: string): string {
  return String(s).replace(/\r\n/g, '\n');
}

/**
 * Is this path safely inside the root?
 *
 * A ledger naming `../../etc/passwd` would otherwise have the settle step open
 * it, which is a file read the user did not ask for driven by a file the user
 * may not have written. Rejected by resolution rather than by string
 * inspection, so `a/../../b` cannot slip through.
 */
function insideRoot(root: string, relPath: string): boolean {
  if (isAbsolute(relPath)) return false;
  const full = resolve(root, relPath);
  return full === root || full.startsWith(root.endsWith(sep) ? root : root + sep);
}

function validEntry(x: unknown, root: string): FixLedgerEntry | null {
  if (!x || typeof x !== 'object') return null;
  const e = x as Record<string, unknown>;
  const str = (v: unknown): string | null => (typeof v === 'string' && v.length ? v : null);
  const ruleId = str(e.ruleId);
  const filePath = str(e.filePath);
  const insertedLine = str(e.insertedLine);
  if (!ruleId || !filePath || !insertedLine) return null;
  if (normalise(insertedLine).trim().length < MIN_INSERTED_CHARS) return null;
  if (!insideRoot(root, filePath)) return null;
  if (typeof e.startLine !== 'number' || !Number.isFinite(e.startLine) || e.startLine < 1) return null;
  const witness = str(e.witness);
  // A short or blank witness is dropped rather than carried: `crossExamine`
  // would refuse it anyway, and an entry that arrives pre-refused is noise.
  const keptWitness = witness && witness.trim().length >= MIN_WITNESS_CHARS ? witness : undefined;
  return {
    ruleId,
    title: str(e.title) ?? ruleId,
    safety: str(e.safety) ?? 'unknown',
    filePath,
    startLine: e.startLine,
    insertedLine,
    ...(keptWitness ? { witness: keptWitness } : {}),
    createdAt: str(e.createdAt) ?? '',
  };
}

const keyOf = (e: FixLedgerEntry): string =>
  `${e.filePath} ${e.startLine} ${e.ruleId} ${normalise(e.insertedLine).trim()}`;

/**
 * Read and validate the ledger.
 *
 * Returns `entries: []` and a `note` for every failure — a missing file, a
 * parse error, a wrong shape. Never throws: a broken ledger must degrade this
 * channel and nothing else, and above all must not stop the scan it is attached
 * to. The distinction that IS preserved is between "no ledger" (no note) and
 * "a ledger this could not read" (a note), because the second is a thing the
 * user should be told rather than a quiet nothing.
 */
export async function readLedger(
  target: string,
  targetIsFile: boolean,
): Promise<{ entries: FixLedgerEntry[]; note?: string; dropped: number }> {
  const root = ledgerRoot(target, targetIsFile);
  const path = ledgerPath(target, targetIsFile);
  let raw: string;
  try {
    const info = await stat(path);
    if (info.size > MAX_LEDGER_BYTES) {
      return { entries: [], dropped: 0, note: `${path} is ${info.size} bytes, over the ${MAX_LEDGER_BYTES} this will read` };
    }
    raw = await readFile(path, 'utf8');
  } catch {
    return { entries: [], dropped: 0 };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { entries: [], dropped: 0, note: `${path} did not parse as JSON: ${(err as Error).message}` };
  }
  const list = (parsed as { entries?: unknown })?.entries;
  if (!Array.isArray(list)) {
    return { entries: [], dropped: 0, note: `${path} has no "entries" array` };
  }
  const entries: FixLedgerEntry[] = [];
  const seen = new Set<string>();
  let dropped = 0;
  for (const item of list) {
    if (entries.length >= MAX_ENTRIES) {
      dropped += 1;
      continue;
    }
    const e = validEntry(item, root);
    if (!e) {
      dropped += 1;
      continue;
    }
    const k = keyOf(e);
    if (seen.has(k)) continue;
    seen.add(k);
    entries.push(e);
  }
  return {
    entries,
    dropped,
    ...(dropped ? { note: `${path}: ${dropped} entr(y/ies) were unusable and ignored` } : {}),
  };
}

async function writeLedger(path: string, entries: FixLedgerEntry[]): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify({ version: 1, entries }, null, 2)}\n`, 'utf8');
}

/**
 * Record what a fixer inserted, merging with whatever is already there.
 *
 * Only ever called when the fixer actually WROTE. A dry run has inserted
 * nothing, and an entry for an edit that was never made is a claim about a file
 * that does not say what the ledger says it says.
 */
export async function recordFixerClaims(
  target: string,
  targetIsFile: boolean,
  claims: readonly ProtectionClaim[],
): Promise<{ path: string; added: number; total: number; evicted: number }> {
  const root = ledgerRoot(target, targetIsFile);
  const path = ledgerPath(target, targetIsFile);
  const existing = (await readLedger(target, targetIsFile)).entries;
  const byKey = new Map(existing.map((e) => [keyOf(e), e]));
  const now = new Date().toISOString();
  let added = 0;
  for (const c of claims) {
    if (!c.sourceProbe || !c.filePath) continue;
    const candidate = validEntry(
      {
        ruleId: c.claimant.replace(/^fixer:/, ''),
        title: c.subject,
        safety: 'recorded',
        filePath: c.filePath,
        startLine: c.startLine ?? 1,
        insertedLine: c.sourceProbe,
        witness: c.witness,
        createdAt: now,
      },
      root,
    );
    if (!candidate) continue;
    const k = keyOf(candidate);
    if (byKey.has(k)) continue;
    byKey.set(k, candidate);
    added += 1;
  }
  // Oldest out first when over the cap. Insertion order is chronological
  // because merged entries keep their original `createdAt` and new ones are
  // appended, so dropping from the front drops the oldest.
  let all = [...byKey.values()];
  let evicted = 0;
  if (all.length > MAX_ENTRIES) {
    evicted = all.length - MAX_ENTRIES;
    all = all.slice(evicted);
  }
  await writeLedger(path, all);
  return { path, added, total: all.length, evicted };
}

/**
 * Turn the ledger into claims, expiring the entries whose edit is gone.
 *
 * The returned claims are all `NOT_OBSERVED`, as every claim from a claimant
 * layer must be. Expired ones carry a note saying why they can never be settled
 * and are removed from the file; live ones are handed to `crossExamine` and may
 * be settled by an artefact observation, which is legal because `fixer` is not
 * `artifact`.
 */
export async function claimsFromLedger(
  target: string,
  targetIsFile: boolean,
): Promise<{ claims: ProtectionClaim[]; expired: ProtectionClaim[]; note?: string }> {
  const root = ledgerRoot(target, targetIsFile);
  const { entries, note } = await readLedger(target, targetIsFile);
  if (!entries.length) return { claims: [], expired: [], ...(note ? { note } : {}) };

  const live: FixLedgerEntry[] = [];
  const claims: ProtectionClaim[] = [];
  const expired: ProtectionClaim[] = [];
  let n = 0;
  for (const e of entries) {
    const base = {
      id: `ledger-claim-${++n}`,
      claimant: `fixer:${e.ruleId}`,
      // ★ Hard-coded, never read from the file. A ledger that could name its own
      // layer could name `artifact` and settle itself, which is the one move
      // `illegalClaimTransition` exists to refuse.
      claimantLayer: 'fixer' as const,
      subject: e.title,
      ...(e.witness ? { witness: e.witness } : {}),
      sourceProbe: e.insertedLine,
      filePath: e.filePath,
      startLine: e.startLine,
      state: 'NOT_OBSERVED' as const,
    };
    let source: string | null = null;
    try {
      source = await readFile(resolve(root, e.filePath), 'utf8');
    } catch {
      source = null;
    }
    if (source === null) {
      expired.push({ ...base, note: `${e.filePath} could not be read, so this recorded edit cannot be shown to still be in the source` });
      continue;
    }
    if (!normalise(source).includes(normalise(e.insertedLine).trim())) {
      expired.push({ ...base, note: 'the edit this claim records is no longer in the source, so there is nothing left to look for in the build' });
      continue;
    }
    live.push(e);
    claims.push(base);
  }
  if (expired.length) {
    // Pruned here rather than left to accumulate: an expired entry can never
    // resolve, and a ledger that only grows becomes a list nobody reads.
    await writeLedger(ledgerPath(target, targetIsFile), live);
  }
  return { claims, expired, ...(note ? { note } : {}) };
}
