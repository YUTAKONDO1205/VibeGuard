// AI-authorship provenance — the observation side of #29b (product lane).
//
// ★★ THE CLAIM LIMIT. READ THIS BEFORE ADDING A FIELD.
//
// Everything in this module is a SELF-REPORT. A `Co-authored-by: Claude` trailer
// exists because somebody's tooling chose to write it down; the overwhelming
// majority of AI-assisted changes carry no marker at all — no trailer, no
// footer, no PR-body section — and nothing here can see them. So the marker set
// has UNKNOWN, and certainly non-uniform, coverage of the thing a reader will
// want it to be about ("which code did an AI write").
//
// Three consequences are structural, not stylistic, and the shapes below exist
// to enforce them:
//
//  1. THE MARKER SET IS NOT A DENOMINATOR. "3 of 500 commits carry a marker"
//     does not mean 0.6% of the work was AI-assisted; it means 3 commits said
//     so. No field in this module reports a rate, and `commitsInspected` is
//     deliberately nested inside `inspected` — a description of the WINDOW that
//     was read — rather than sitting beside the marker list where dividing one
//     by the other would look natural.
//  2. ABSENCE IS NOT EVIDENCE OF ABSENCE. There is no `aiAuthored: false`, and
//     there never can be. The only two states this module can distinguish are
//     "a marker was observed" and "nothing was observed", and the second one is
//     the same state as "we did not look" — see the emission rule in index.ts.
//  3. NO FIELD IS A SCORE. There is no `risk`, no `confidence`, no `severity`
//     here, and a marker never touches a finding's severity or confidence. If a
//     future caller wants "AI-written therefore dangerous", it will have to
//     invent the number itself, in its own file, where the invention is visible.
//     The field names are chosen so that reading one as a verdict requires
//     actively misnaming it: `observedAuthorshipMarkers`, `matchedOn`,
//     `occurrences`, `claimLimit`.
//
// `AI_PROVENANCE_CLAIM_LIMIT` is carried IN the emitted JSON rather than left in
// this comment, because the consumer of a SARIF property bag is a dashboard, not
// a reader of this file. A caveat that only exists in the source is a caveat
// that does not travel with the data.
//
// ★ WHY THIS LIVES IN sarif-adapter AND NOT IN findings-schema
//
// findings-schema is the vocabulary shared by everything that handles a
// FINDING — the rules, the analyzer, the Chrome extension, the VS Code
// extension. Provenance is none of those things: it is repository metadata that
// exists for exactly one consumer (the SARIF run property bag), it never
// attaches to a Finding, and it is unobtainable in the one environment
// findings-schema most has to stay light for. The Chrome extension scans a
// textarea inside a browser tab; there is no git there, no repository, and no
// PR body file, so a type placed in findings-schema would be a type that
// package's biggest consumer can never populate. Put where it is used.
//
// ★ WHY THE READER IS SPLIT OUT INTO provenance-node.ts
//
// This file is pure: text in, observation out, no I/O, no clock, no network.
// The half that runs `git log` lives in `./provenance-node.ts` behind the
// package's `./node` subpath, mirroring `@vibeguard/analyzer-core`'s `./browser`
// split for the same reason in the other direction. sarif-adapter is bundled
// into the VS Code extension (esbuild, `--platform=node`, so a builtin would
// work there today) but the boundary is cheap now and expensive to retrofit
// after something bundles this for a browser. Keeping `node:child_process` out
// of the package's main entry point is the whole point.
//
// ZERO TRANSMISSION: nothing in this module or its Node half opens a socket.
// The assistant registry below is a literal — there is no lookup service, no
// "is this a bot account" API call, and no way for a scanned repository to
// cause an outbound request.

/**
 * The sentence that travels with the data. Emitted verbatim into the SARIF
 * property bag so a consumer three systems away is told what the numbers are
 * not, without having to find this file.
 */
export const AI_PROVENANCE_CLAIM_LIMIT =
  'Self-reported markers only. These are declarations found in commit trailers, commit ' +
  'message footers and PR body text; they are not a detection of AI-generated code. Most ' +
  'AI-assisted changes carry no marker, so the absence of a marker means nothing was ' +
  'declared — not that no assistant was involved. Counts describe the markers observed and ' +
  'must not be used as a denominator, converted into a rate, or read as a risk score.';

/**
 * The structural place a marker was read out of.
 *
 * This is a CHANNEL, not a confidence band. It is recorded because "a git
 * trailer in a merged commit" and "a heading somebody typed into a PR
 * description" are different acts by different actors, and a consumer that
 * cannot tell them apart cannot decide how much either is worth.
 */
export type AiMarkerChannel =
  | 'git-trailer'
  | 'commit-message-footer'
  | 'commit-subject-declaration'
  | 'pr-body-trailer'
  | 'pr-body-section';

/**
 * What actually matched. Kept because the three are not equally strong evidence
 * and collapsing them would be the first step toward treating a marker as a
 * verdict:
 *
 *   'email-address'     — the identity carried an address this file registers as
 *                         belonging to an assistant's tooling. Strongest: a
 *                         human does not accidentally commit as
 *                         `noreply@anthropic.com`.
 *   'display-name'      — the identity's display name was EXACTLY a registered
 *                         assistant name. Weaker; see the exact-match argument
 *                         on `matchesAssistant`.
 *   'declaration-only'  — the structure itself declares AI authorship
 *                         (`AI-Assisted-By:`, an `AI disclosure` PR section) and
 *                         names no tool. `assistant` is null for these.
 */
export type AiMarkerMatchedOn = 'email-address' | 'display-name' | 'declaration-only';

/**
 * One observed declaration, aggregated across the commits (or PR body lines)
 * that carried the identical declaration.
 *
 * Note what is NOT here: no raw email address, no committer name, no commit SHA,
 * no line number. SARIF produced by the GitHub Action is uploaded to code
 * scanning and rendered in a UI, and a marker match is fallible — a human whose
 * display name happens to be exactly a registered assistant name would have had
 * their address republished into a security dashboard by a component that
 * exists to count declarations. The registry id is all a consumer needs to know
 * WHICH assistant was declared, and it cannot identify a person.
 */
export interface AiAuthorshipMarker {
  channel: AiMarkerChannel;
  /** The artifact the text came from: `git-log`, or the label the caller gave the PR body. */
  readFrom: string;
  /** The trailer key or heading that carried it, normalised to lowercase. */
  field: string;
  /** Registry id of the assistant named, or null when the structure declared AI authorship without naming one. */
  assistant: string | null;
  matchedOn: AiMarkerMatchedOn;
  /** Distinct commits (or distinct PR-body lines) carrying this exact declaration. */
  occurrences: number;
}

/**
 * What was read, so a consumer can see the shape of the window rather than
 * guess it. `commitsInspected` is a WINDOW SIZE, not a population: see claim
 * limit (1) above for why it is nested here instead of sitting next to the
 * marker list.
 */
export interface AiProvenanceInspection {
  /** Channels actually read this run, sorted. Absent channels were not consulted. */
  channelsRead: string[];
  commitsInspected: number;
  /**
   * True when the log handed in already had more records than this module will
   * parse. Recorded because a truncated window is a different thing from an
   * exhaustive one, and silently capping would let "no markers" mean "no markers
   * in the part we bothered to read".
   */
  commitWindowTruncated: boolean;
}

export interface AiProvenanceObservation {
  schemaVersion: 1;
  observedAuthorshipMarkers: AiAuthorshipMarker[];
  inspected: AiProvenanceInspection;
  /** Always `AI_PROVENANCE_CLAIM_LIMIT`. Carried so the caveat travels with the data. */
  claimLimit: string;
}

export interface AiProvenanceInput {
  /**
   * Raw `git log` output in the record format `provenance-node.ts` requests:
   * NUL-separated records, each `<sha>\n<full message body>`. Undefined means
   * the channel was not consulted, which is NOT the same as an empty log (a
   * repository with zero commits), and the two produce different
   * `channelsRead`.
   */
  gitLog?: string;
  /** PR body text, verbatim, as supplied by an input file. */
  prBody?: string;
  /** Label recorded as `readFrom` for PR-body markers. Defaults to `pr-body`. */
  prBodyLabel?: string;
}

// ---------------------------------------------------------------------------
// Caps. Every one of these bounds work done per scanned repository; none of them
// changes what is FOUND in a normal repository, they only stop a hostile or
// pathological history from turning a provenance read into a denial of service.
// The scanned repository is attacker-influenced input (that is the premise of
// this project's own threat model), so a commit message is untrusted text.
// ---------------------------------------------------------------------------

/** Records parsed out of a `git log` blob, whatever the caller asked git for. */
const MAX_COMMITS_PARSED = 2000;
/** Lines examined per commit message. Trailers live at the end, but a message with 200+ lines is a pasted diff, not a message. */
const MAX_MESSAGE_LINES = 200;
/** Lines examined in a PR body. */
const MAX_PR_BODY_LINES = 2000;
/**
 * Lines longer than this are skipped outright. A git trailer is short; a
 * 10,000-character line is minified source or a pasted blob, and running six
 * regexes over it per commit buys nothing.
 */
const MAX_LINE_LENGTH = 400;
/** Lines scanned after a designated PR-body heading before the section is considered over. */
const MAX_SECTION_LINES = 40;
/** Distinct aggregated markers emitted. Beyond this the list is noise in a property bag. */
const MAX_MARKERS = 64;

// ---------------------------------------------------------------------------
// The assistant registry.
//
// ★ EXACT IDENTITIES ONLY — THE SUBSTRING VERSION WAS REFUSED
//
// The tempting implementation is `identity.toLowerCase().includes('claude')`.
// It is wrong in the direction that costs the most here. `Co-authored-by: Marcus
// Cursor <marcus@corp.example>` is a human; `Co-authored-by: Jean-Claude Dupont
// <jc@corp.example>` is a human; `Copilot Systems Ltd` is a company. A substring
// test reports all three as AI authorship, in a property bag that a dashboard
// will render next to security findings — and because the emitted object
// carries no raw identity (deliberately, see AiAuthorshipMarker), nobody
// downstream could even tell that it had misfired.
//
// So membership is decided by EXACT identity:
//   - the full lowercased email address is one this registry lists, or
//   - the email local-part is exactly a registered bot local-part, or ends with
//     `+<local-part>` (GitHub's `198982749+Copilot@users.noreply.github.com`
//     form), or
//   - the WHOLE normalised display name equals a registered name.
//
// The cost of exactness is false negatives: an assistant whose tooling writes an
// address this file does not list produces no marker. That is the correct
// direction to be wrong in. A missing marker degrades to "nothing was declared",
// which the claim limit already says means nothing — a wrong marker asserts
// something false about a named tool and, worse, about a person.
//
// Corporate domains are deliberately NOT registered as blanket matches.
// `anthropic.com` and `openai.com` are also the addresses of the humans who work
// there; `noreply@anthropic.com` is a machine. Registering the domain would make
// every employee commit an AI-authorship marker.
//
// ★★ NO BARE GIVEN NAME IS REGISTERED, AND THAT WAS A LATE CORRECTION
//
// The first version of this table listed `claude`, `devin` and `jules` as
// display names. All three are common human given names — Claude is one of the
// most common male given names in France — so `Co-authored-by: Claude
// <claude@corp.example>` would have produced an AI-authorship marker for a
// person. `jules` and `devin` are the same defect in English and French
// respectively.
//
// They are gone. Only the compound forms a tool actually writes survive
// (`claude code`, `devin ai`, `google labs jules`), and the bare-name case is
// covered by the address instead. That costs nothing where it matters: over this
// repository's own 221-commit window, all 78 Claude trailers matched on
// `noreply@anthropic.com`, i.e. `matchedOn: 'email-address'` — not one of them
// needed the display name. `codex`, `copilot`, `cursor` and `gemini` stay,
// because none of them is a human given name.
// ---------------------------------------------------------------------------

interface AiAssistantIdentity {
  /** Stable id emitted as `marker.assistant`. Lowercase, hyphenated. */
  id: string;
  /** Full lowercased addresses issued by this assistant's tooling. */
  emailAddresses: readonly string[];
  /** Local-parts (before `@`) issued by this assistant's bot account. */
  emailLocalParts: readonly string[];
  /** Whole display names, normalised. Compared with `===`, never with `includes`. */
  displayNames: readonly string[];
}

const AI_ASSISTANTS: readonly AiAssistantIdentity[] = [
  {
    id: 'claude',
    emailAddresses: ['noreply@anthropic.com'],
    emailLocalParts: ['claude[bot]', 'claude-code[bot]'],
    // Not `claude` — see the bare-given-name argument above.
    displayNames: ['claude code', 'claude ai'],
  },
  {
    id: 'codex',
    emailAddresses: ['noreply@openai.com'],
    emailLocalParts: ['chatgpt-codex-connector[bot]', 'codex[bot]'],
    displayNames: ['codex', 'openai codex', 'chatgpt codex connector'],
  },
  {
    id: 'copilot',
    emailAddresses: [],
    emailLocalParts: ['copilot', 'copilot[bot]', 'github-copilot[bot]'],
    displayNames: ['copilot', 'github copilot', 'copilot swe agent'],
  },
  {
    id: 'cursor',
    emailAddresses: ['cursoragent@cursor.com'],
    emailLocalParts: ['cursoragent', 'cursor[bot]'],
    displayNames: ['cursor', 'cursor agent'],
  },
  {
    id: 'devin',
    emailAddresses: [],
    emailLocalParts: ['devin-ai-integration[bot]'],
    // Not `devin` — a given name.
    displayNames: ['devin ai'],
  },
  {
    id: 'gemini',
    emailAddresses: [],
    emailLocalParts: ['gemini-code-assist[bot]'],
    displayNames: ['gemini', 'gemini code assist'],
  },
  {
    id: 'jules',
    emailAddresses: [],
    emailLocalParts: ['google-labs-jules[bot]'],
    // Not `jules` — a given name.
    displayNames: ['google labs jules'],
  },
] as const;

/** Registry ids, exported so a caller can render a legend without re-deriving the list. */
export const KNOWN_AI_ASSISTANT_IDS: readonly string[] = AI_ASSISTANTS.map((a) => a.id);

// ---------------------------------------------------------------------------
// Lexical helpers.
//
// Every regex here is anchored and BOUNDED. `[^\S\r\n]{0,4}` is the repo's
// horizontal-whitespace idiom; `\s*` next to another quantifier is the shape
// that produced this project's A1 ReDoS findings, and a commit message is
// attacker-supplied text arriving from a repository under scan, so the bound is
// the only thing standing between a crafted history and a hung scan.
// ---------------------------------------------------------------------------

/**
 * A git trailer line. Deliberately strict, and strict in ways that matter:
 *
 *  - anchored at column 0 with NO leading-whitespace tolerance, because a git
 *    trailer is unindented by definition and an indented `Co-authored-by:` is
 *    quoted text (a pasted diff, a nested commit message, a code block body);
 *  - no space permitted before the colon, for the same reason — `Co-authored-by
 *    : x` is prose;
 *  - the key is bounded at 32 characters, which every real trailer key fits
 *    inside and a pasted URL does not.
 */
const TRAILER_LINE = /^([A-Za-z][A-Za-z0-9-]{0,31}):[^\S\r\n]{0,4}(.{0,240})$/;

/**
 * `Display Name <local@domain>`. `[^<>]` on both halves means the two parts
 * cannot overlap, so there is no ambiguity for a backtracking engine to explore
 * — the whole match is decided in one pass regardless of input.
 */
const TRAILER_IDENTITY = /^([^<>]{0,120})<([^<>]{1,200})>$/;

/** Markdown fence opener/closer. Used to skip code blocks, never to parse them. */
const FENCE_LINE = /^(?:```|~~~)/;

/** ATX heading. Bounded on both the hashes and the text. */
const MD_HEADING = /^#{1,6}[^\S\r\n]{1,4}(.{1,120})$/;

/** Unordered list item. */
const MD_LIST_ITEM = /^[-*][^\S\r\n]{1,4}(.{1,80})$/;

/** Leading decoration on a footer line — an emoji, a bullet, a dash. Bounded at 8. */
const LEADING_NON_LETTERS = /^[^A-Za-z]{0,8}/;

/** `Generated with <label>`. The label is extracted with string ops, not a nested quantifier. */
const GENERATED_WITH = /^Generated with[^\S\r\n]{1,4}(.{1,80})$/i;

/**
 * Subject-line declarations. Two exact forms, not one loose one.
 *
 * ★ THE `[AI]` PREFIX WAS REFUSED. A bare `[AI] ...` or `ai:` subject prefix is
 * genuinely ambiguous: in any repository that BUILDS an AI feature it is a
 * conventional-commit scope meaning "the AI subsystem", not a declaration about
 * who wrote the patch. `feat(ai): tune the prompt` is a human commit about AI.
 * There is no lexical way to tell the two apart, and the corpus this project
 * ships against is full of AI products, so the ambiguous form would fire mostly
 * on the wrong repositories. `ai-generated:` / `ai-assisted:` / `ai-written:`
 * cannot mean "the AI subsystem" — they are about authorship or they are
 * nothing.
 */
const SUBJECT_DECLARATION_BRACKET = /^\[(ai-generated|ai-assisted|ai-written)\]/i;
const SUBJECT_DECLARATION_PLAIN = /^(ai-generated|ai-assisted|ai-written):/i;

/** A trailing `[bot]` / `(bot)` decoration on a display name. */
const BOT_SUFFIX = /[[(]bot[\])]$/;

/**
 * Trailer keys whose KEY alone declares AI authorship. These need no registered
 * assistant in the value — the author wrote "AI" into the key on purpose — and
 * produce `matchedOn: 'declaration-only'`.
 */
const DECLARING_TRAILER_KEYS: ReadonlySet<string> = new Set([
  'ai-assisted-by',
  'ai-generated-by',
  'ai-authored-by',
  'assisted-by-ai',
]);

/**
 * Trailer keys that carry an identity but say nothing about AI on their own.
 * A marker follows ONLY if the value names a registered assistant — otherwise
 * `Co-authored-by:` would flag every pair-programming commit in existence, and
 * `Generated-by:` would flag every codegen tool.
 */
const IDENTITY_TRAILER_KEYS: ReadonlySet<string> = new Set([
  'co-authored-by',
  'assisted-by',
  'generated-by',
  'authored-by',
]);

/**
 * PR-body headings that designate an authorship-disclosure section. Closed set,
 * matched on the WHOLE normalised heading text.
 *
 * `ai usage` and `ai features` are deliberately absent: in a product repository
 * those headings describe the product, not the patch, which is the same
 * ambiguity that got the `[AI]` subject prefix refused above.
 */
const DESIGNATED_PR_SECTIONS: ReadonlySet<string> = new Set([
  'ai assistance',
  'ai disclosure',
  'ai authorship',
  'ai provenance',
  'ai-assisted development',
  'ai tools used',
]);

/** Lowercase, tabs to spaces, collapse runs of spaces, trim. Pure string ops — no quantifier to bound. */
function normaliseLabel(raw: string): string {
  return raw.replace(/\t/g, ' ').trim().toLowerCase().split(' ').filter(Boolean).join(' ');
}

/**
 * Which registered assistant, if any, this `Name <email>` identity is — and on
 * what evidence. Returns null for everything else, which is the overwhelmingly
 * common case (every human co-author).
 */
function matchesAssistant(
  displayName: string,
  email: string,
): { assistant: string; matchedOn: 'email-address' | 'display-name' } | null {
  const addr = normaliseLabel(email);
  const at = addr.lastIndexOf('@');
  const localPart = at > 0 ? addr.slice(0, at) : '';
  // GitHub's noreply form prefixes the account id: `198982749+Copilot@...`.
  const plus = localPart.lastIndexOf('+');
  const bareLocalPart = plus >= 0 ? localPart.slice(plus + 1) : localPart;

  for (const a of AI_ASSISTANTS) {
    if (addr && a.emailAddresses.includes(addr)) return { assistant: a.id, matchedOn: 'email-address' };
    if (localPart && (a.emailLocalParts.includes(localPart) || a.emailLocalParts.includes(bareLocalPart))) {
      return { assistant: a.id, matchedOn: 'email-address' };
    }
  }
  // Display name only after every address test has failed, so the stronger
  // evidence always wins the `matchedOn` field when both would match.
  const name = normaliseLabel(displayName).replace(BOT_SUFFIX, '').trim();
  if (!name) return null;
  for (const a of AI_ASSISTANTS) {
    if (a.displayNames.includes(name)) return { assistant: a.id, matchedOn: 'display-name' };
  }
  return null;
}

/** The registered assistant a bare label (`Claude Code`, `Cursor`) names, or null. */
function assistantByName(label: string): string | null {
  const name = normaliseLabel(label).replace(BOT_SUFFIX, '').trim();
  if (!name) return null;
  for (const a of AI_ASSISTANTS) if (a.displayNames.includes(name)) return a.id;
  return null;
}

/**
 * The assistant named by a trailer VALUE, in either of the two forms real
 * tooling writes: `Claude <noreply@anthropic.com>` and a bare `Cursor`.
 *
 * One function rather than the same ternary in both trailer branches, because
 * the two branches disagreeing about what counts as "names an assistant" is
 * precisely the divergence that makes a marker set unreadable.
 */
function namedAssistantIn(
  value: string,
): { assistant: string; matchedOn: 'email-address' | 'display-name' } | null {
  const identity = TRAILER_IDENTITY.exec(value);
  if (identity) return matchesAssistant(identity[1]!, identity[2]!);
  const byName = assistantByName(value);
  return byName ? { assistant: byName, matchedOn: 'display-name' } : null;
}

// ---------------------------------------------------------------------------
// git log parsing
// ---------------------------------------------------------------------------

export interface GitLogRecord {
  sha: string;
  message: string;
}

/**
 * Split the NUL-separated `git log -z --format=%H%n%B` blob into records.
 *
 * NUL is the separator because it is the one byte a commit message cannot
 * contain — git rejects it — so no crafted message can forge a record boundary
 * and inject a fake commit into the count. A textual sentinel could.
 *
 * `truncated` is reported rather than silently applied: see
 * `AiProvenanceInspection.commitWindowTruncated`.
 */
export function parseGitLogRecords(raw: string): { records: GitLogRecord[]; truncated: boolean } {
  const chunks = raw.split('\0').filter((c) => c.trim() !== '');
  const truncated = chunks.length > MAX_COMMITS_PARSED;
  const records: GitLogRecord[] = [];
  for (const chunk of chunks.slice(0, MAX_COMMITS_PARSED)) {
    // `%H%n%B`: the first line is the sha, everything after it is the message.
    const nl = chunk.indexOf('\n');
    if (nl < 0) {
      // A record with no message body at all (`git log --format=%H` alone, or a
      // commit whose message is empty). Keep it so the commit count stays
      // honest; it simply carries nothing to match.
      records.push({ sha: chunk.trim(), message: '' });
      continue;
    }
    records.push({ sha: chunk.slice(0, nl).trim(), message: chunk.slice(nl + 1) });
  }
  return { records, truncated };
}

/**
 * Message lines that are eligible to carry a trailer or footer.
 *
 * ★ THE NEGATIVE CONDITIONS, WHICH ARE THE POINT OF THIS FUNCTION.
 *
 * A commit message routinely quotes other text: a revert quotes the reverted
 * message, a squash quotes every squashed subject, a bug report pasted into the
 * body quotes a log, and a message with a fenced block quotes code. Any of those
 * can contain a real-looking `Co-authored-by:` line that belongs to a DIFFERENT
 * commit, or to no commit at all. Counting those would inflate `occurrences`
 * with duplicates of one declaration and — for a pasted example — invent one.
 *
 * So three classes are dropped before any pattern runs:
 *   - indented lines (a git trailer is unindented; indentation means quoting);
 *   - lines inside a ``` or ~~~ fence;
 *   - lines beginning with `>` (email/issue quoting).
 */
function eligibleLines(message: string, limit: number): string[] {
  const out: string[] = [];
  let inFence = false;
  const lines = message.split('\n');
  for (let i = 0; i < lines.length && i < limit; i++) {
    const line = lines[i]!.replace(/\r$/, '');
    if (FENCE_LINE.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    if (line.length > MAX_LINE_LENGTH) continue;
    if (line.length === 0) {
      out.push('');
      continue;
    }
    // Indented or quoted: not a trailer, whatever it looks like.
    const first = line[0]!;
    if (first === ' ' || first === '\t' || first === '>') continue;
    out.push(line);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

type MarkerKey = string;

/**
 * Accumulates markers, counting DISTINCT carriers rather than raw hits.
 *
 * A commit that writes `Co-authored-by: Claude <noreply@anthropic.com>` twice
 * (git itself deduplicates trailers on rebase, but `--squash` does not always)
 * is one commit declaring one thing. `occurrences` is a count of commits, so the
 * carrier id gates the increment.
 */
class MarkerTally {
  private readonly byKey = new Map<MarkerKey, AiAuthorshipMarker>();
  private readonly seen = new Map<MarkerKey, Set<string>>();

  add(marker: Omit<AiAuthorshipMarker, 'occurrences'>, carrierId: string): void {
    const key = [marker.channel, marker.readFrom, marker.field, marker.assistant ?? '', marker.matchedOn].join(
      '\u0000',
    );
    let carriers = this.seen.get(key);
    if (!carriers) {
      carriers = new Set<string>();
      this.seen.set(key, carriers);
    }
    if (carriers.has(carrierId)) return;
    carriers.add(carrierId);
    const existing = this.byKey.get(key);
    if (existing) existing.occurrences += 1;
    else this.byKey.set(key, { ...marker, occurrences: 1 });
  }

  /** Sorted deterministically: the emitted JSON must not depend on commit order. */
  drain(): AiAuthorshipMarker[] {
    return Array.from(this.byKey.values())
      .sort(
        (a, b) =>
          a.channel.localeCompare(b.channel) ||
          a.field.localeCompare(b.field) ||
          (a.assistant ?? '').localeCompare(b.assistant ?? '') ||
          a.matchedOn.localeCompare(b.matchedOn) ||
          a.readFrom.localeCompare(b.readFrom),
      )
      .slice(0, MAX_MARKERS);
  }
}

/** Trailers and footers in one commit message. */
function scanCommitMessage(record: GitLogRecord, tally: MarkerTally): void {
  const lines = eligibleLines(record.message, MAX_MESSAGE_LINES);
  const carrier = record.sha || record.message.slice(0, 64);

  // The subject is the first line, and only the first line: a declaration
  // prefix means something at the head of a message and nothing in its body.
  //
  // Taken from the RAW message rather than from `lines`, because
  // `eligibleLines` drops over-long and quoted lines — so on a message with a
  // 500-character subject, `lines[0]` would be a BODY line silently promoted
  // into subject position, and a body line reading `AI-generated: is how we
  // would have tagged it` would become a declaration.
  const firstNewline = record.message.indexOf('\n');
  const subject = (firstNewline < 0 ? record.message : record.message.slice(0, firstNewline)).replace(
    /\r$/,
    '',
  );
  const bracket = SUBJECT_DECLARATION_BRACKET.exec(subject);
  const plain = bracket ? null : SUBJECT_DECLARATION_PLAIN.exec(subject);
  const declaration = bracket ?? plain;
  if (declaration) {
    tally.add(
      {
        channel: 'commit-subject-declaration',
        readFrom: 'git-log',
        field: declaration[1]!.toLowerCase(),
        assistant: null,
        matchedOn: 'declaration-only',
      },
      carrier,
    );
  }

  for (const line of lines) {
    const trailer = TRAILER_LINE.exec(line);
    if (trailer) {
      addTrailerMarker(trailer[1]!, trailer[2]!, 'git-trailer', 'git-log', carrier, tally);
      continue;
    }
    // `🤖 Generated with [Claude Code](https://claude.com/claude-code)` and its
    // relatives. Matched only when the line STARTS with the phrase after its
    // decoration is stripped — "we generated with a script" in prose does not
    // start a line with `Generated with`, and requiring the label to be an exact
    // registered assistant name closes the rest.
    const stripped = line.replace(LEADING_NON_LETTERS, '');
    const footer = GENERATED_WITH.exec(stripped);
    if (!footer) continue;
    const assistant = assistantByName(extractFooterLabel(footer[1]!));
    if (!assistant) continue;
    tally.add(
      {
        channel: 'commit-message-footer',
        readFrom: 'git-log',
        field: 'generated with',
        assistant,
        matchedOn: 'display-name',
      },
      carrier,
    );
  }
}

/**
 * The tool name out of a `Generated with ...` tail, using indexOf rather than a
 * second regex. `[Claude Code](https://…)` → `Claude Code`; `Cursor` → `Cursor`;
 * `Claude Code (https://…)` → `Claude Code`. A nested-quantifier regex would do
 * the same job and would be the third place in this file where an unbounded
 * shape could creep in.
 */
function extractFooterLabel(tail: string): string {
  const t = tail.trim();
  if (t.startsWith('[')) {
    const close = t.indexOf(']');
    return close > 1 ? t.slice(1, close) : '';
  }
  const paren = t.indexOf('(');
  return paren > 0 ? t.slice(0, paren) : t;
}

/** Shared by the commit and PR-body trailer paths — the rules are identical. */
function addTrailerMarker(
  rawKey: string,
  rawValue: string,
  channel: 'git-trailer' | 'pr-body-trailer',
  readFrom: string,
  carrier: string,
  tally: MarkerTally,
): void {
  const key = rawKey.toLowerCase();
  const value = rawValue.trim();

  if (DECLARING_TRAILER_KEYS.has(key)) {
    // The key is the declaration. If the value ALSO names a registered
    // assistant, say so — that is strictly more information — but the marker
    // stands either way.
    const named = namedAssistantIn(value);
    tally.add(
      {
        channel,
        readFrom,
        field: key,
        assistant: named?.assistant ?? null,
        matchedOn: named?.matchedOn ?? 'declaration-only',
      },
      carrier,
    );
    return;
  }

  if (!IDENTITY_TRAILER_KEYS.has(key)) return;
  const named = namedAssistantIn(value);
  if (!named) return;
  tally.add(
    { channel, readFrom, field: key, assistant: named.assistant, matchedOn: named.matchedOn },
    carrier,
  );
}

/**
 * PR body: trailer lines anywhere, plus a designated disclosure section.
 *
 * The section arm exists because a PR template's checkbox is the one place a
 * project can ASK for the declaration, and a heading is the only structure
 * markdown gives it. It is still a structure match, not a prose match: the
 * heading text must equal a member of the closed set exactly, and the assistant
 * names that follow are read only out of list items whose whole text is a
 * registered name — so a sentence in the section that mentions Copilot in
 * passing contributes nothing.
 */
function scanPrBody(body: string, label: string, tally: MarkerTally): void {
  const lines = eligibleLines(body, MAX_PR_BODY_LINES);
  let sectionLinesLeft = 0;
  let sectionField = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    const heading = MD_HEADING.exec(line);
    if (heading) {
      const text = normaliseLabel(heading[1]!.replace(/[#:]{1,4}$/, ''));
      if (DESIGNATED_PR_SECTIONS.has(text)) {
        sectionField = text;
        sectionLinesLeft = MAX_SECTION_LINES;
        tally.add(
          {
            channel: 'pr-body-section',
            readFrom: label,
            field: text,
            assistant: null,
            matchedOn: 'declaration-only',
          },
          `section:${text}`,
        );
      } else {
        // Any other heading ends the section: the disclosure is over.
        sectionLinesLeft = 0;
        sectionField = '';
      }
      continue;
    }

    const trailer = TRAILER_LINE.exec(line);
    if (trailer) {
      addTrailerMarker(trailer[1]!, trailer[2]!, 'pr-body-trailer', label, `line:${i}`, tally);
      // A trailer inside the section is still a trailer; do not also read it as
      // a list item below.
      if (sectionLinesLeft > 0) sectionLinesLeft -= 1;
      continue;
    }

    if (sectionLinesLeft <= 0) continue;
    sectionLinesLeft -= 1;
    const item = MD_LIST_ITEM.exec(line);
    if (!item) continue;
    // A checked task-list item (`- [x] Claude`) carries the same name after its
    // marker; an unchecked one (`- [ ] Claude`) is a box the author did NOT
    // tick, and reading it as a declaration would turn every unfilled template
    // into a marker. Only the checked form is unwrapped.
    const itemText = unwrapTaskItem(item[1]!);
    if (itemText === null) continue;
    const assistant = assistantByName(itemText);
    if (!assistant) continue;
    tally.add(
      {
        channel: 'pr-body-section',
        readFrom: label,
        field: sectionField,
        assistant,
        matchedOn: 'display-name',
      },
      `line:${i}`,
    );
  }
}

/**
 * `[x] Claude` → `Claude`; `[ ] Claude` → null (an unticked box declares
 * nothing); `Claude` → `Claude`.
 */
function unwrapTaskItem(text: string): string | null {
  const t = text.trim();
  if (!t.startsWith('[')) return t;
  const close = t.indexOf(']');
  if (close !== 2) return t;
  const box = t[1]!;
  if (box === ' ') return null;
  return t.slice(close + 1).trim();
}

/**
 * Read every supplied channel and report what was declared.
 *
 * Always returns an observation, even when nothing was found. The decision to
 * OMIT the SARIF key when the marker list is empty belongs to the emitter (see
 * `toSarif` in ./index.ts), not here: this function's contract is "report what
 * was seen", and a caller that wants to log "read 500 commits, found nothing"
 * must be able to.
 */
export function collectAiProvenance(input: AiProvenanceInput): AiProvenanceObservation {
  const tally = new MarkerTally();
  const channelsRead: string[] = [];
  let commitsInspected = 0;
  let commitWindowTruncated = false;

  if (input.gitLog !== undefined) {
    channelsRead.push('git-log');
    const { records, truncated } = parseGitLogRecords(input.gitLog);
    commitsInspected = records.length;
    commitWindowTruncated = truncated;
    for (const record of records) scanCommitMessage(record, tally);
  }

  if (input.prBody !== undefined) {
    const label = input.prBodyLabel && input.prBodyLabel.trim() !== '' ? input.prBodyLabel : 'pr-body';
    channelsRead.push(label);
    scanPrBody(input.prBody, label, tally);
  }

  return {
    schemaVersion: 1,
    observedAuthorshipMarkers: tally.drain(),
    inspected: {
      channelsRead: channelsRead.slice().sort(),
      commitsInspected,
      commitWindowTruncated,
    },
    claimLimit: AI_PROVENANCE_CLAIM_LIMIT,
  };
}
