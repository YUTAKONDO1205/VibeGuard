// The adjudicator: given the bytes an agent is about to write, decide whether
// they may land, and say why.
//
// ══════════════════════════════════════════════════════════════════════════
// ★★ THE DESIGN QUESTION: DOES THIS TOOL WRITE THE FILE, OR ONLY ADJUDICATE?
// ══════════════════════════════════════════════════════════════════════════
//
// IT ONLY ADJUDICATES. No SHIPPED module here imports `node:fs` — `guard.ts`,
// `server.ts`, `protocol.ts`, `main.ts` and `index.ts` have no filesystem
// capability at all, and that is the single most important sentence in this
// file. (`server.test.ts` does read from disk, to walk this directory and
// assert the property; a test that proves the absence has to be able to look.)
// The four arguments, in the order that decided it:
//
// 1. WRITING BUYS NO ENFORCEMENT, so it is pure cost. The tempting story is
//    "if the guard performs the write, the guard cannot be bypassed". It can:
//    the client chooses which tool to call. Any agent able to call this server
//    is, by construction, an agent with tools — including whatever filesystem
//    or shell tool it was already using to edit code. Making this server a
//    writer does not remove that tool; it adds a second one. Enforcement lives
//    in the CLIENT's tool allowlist, one layer up, and no amount of capability
//    down here can manufacture it. A mechanism that adds power without adding
//    the guarantee it was added for is a mechanism to delete.
//
// 2. THE PRODUCT'S CLAIM IS "WE DO NOT WIDEN THE ATTACK SURFACE". An MCP server
//    that writes is an arbitrary-file-write primitive reachable by anything
//    that can speak newline JSON-RPC to a pipe — and MCP servers are launched
//    by editors, wrapped by proxies, and increasingly exposed over transports
//    their author did not choose. Confining it would mean a root allowlist,
//    symlink resolution, and a path-traversal policy: a configuration system,
//    which this PoC is explicitly not building, guarding a capability it does
//    not need. VibeGuard would then ship a file-writing daemon in the name of
//    security. The security tool becoming the most valuable target in the
//    toolchain is the failure mode this whole product line argues against.
//
// 3. THE SCAN IS PURE, AND THAT IS WHY IT AGREES ACROSS FOUR CHANNELS. `scan()`
//    is a function from (text, language) to findings, with no I/O anywhere in
//    it — which is exactly why the Chrome extension, which has no filesystem at
//    all, runs the same engine as the CLI. Bolting a write onto the one caller
//    that happens to have a filesystem would make this the only channel whose
//    behaviour depends on the disk, and would put a `write()` inside a
//    request/response cycle that currently cannot fail for environmental
//    reasons (EACCES, ENOSPC, EROFS, a read-only container).
//
// 4. A REFUSAL IS THE ONLY OUTPUT THAT MATTERS, and it is a pure value. Every
//    interesting behaviour here — the finding list, the reason discriminant,
//    the fail-closed path — is observable, testable, and reproducible without a
//    temp directory. That is not a convenience; a guard whose verdict can only
//    be tested by observing the filesystem is a guard whose tests are slower
//    than the thing they test and will be skipped.
//
// THE HONEST COST, stated because the argument is not free: this makes the
// guardrail ADVISORY. An agent that ignores the refusal and writes anyway is not
// stopped by anything in this package. That is a real limitation and it is
// written in the README rather than glossed; the mitigation is client-side (the
// agent is given this tool and not a raw writer), and the mitigation is out of
// this package's reach by the argument in (1) above.

import {
  MAX_FILE_BYTES,
  detectLanguageFromPath,
  scan as coreScan,
  type AnalyzerOptions,
} from '@vibeguard/analyzer-core';
import {
  compareSeverity,
  type Finding,
  type ScanDegradation,
  type ScanRequest,
  type ScanResponse,
  type Severity,
} from '@vibeguard/findings-schema';

/**
 * The severity at which a write is refused: `high` and above, i.e. `high` and
 * `critical`.
 *
 * ★ WHY THIS NUMBER AND NOT ANOTHER
 *
 * It is not a new policy. `--fail-on high` is already the CLI's default, so it
 * is already what the GitHub Action refuses to merge. Setting the guard to the
 * same line means a blocked write is never a write that would have survived
 * review — the guard moves an existing verdict earlier in time, which is the
 * entire thesis of this package, rather than inventing a stricter one that only
 * the guard enforces. An agent that satisfies the guard has, by construction,
 * satisfied the gate its pull request will meet.
 *
 * ★ WHY NOT `medium`, which `isSecurityJudgementSeverity` includes
 *
 * `findings-schema` treats critical/high/medium as "security judgements" — the
 * band that a suppression may not silence. Blocking is a strictly harsher
 * response than refusing-to-silence, so it needs a stricter bar. Medium is
 * where the low-confidence rules live (`VG-CRYPTO-001` ships with
 * `defaultConfidence: 'low'`, and it fires on a bare md5 call in any language), and
 * a guard that blocks on those puts the agent in a loop it cannot exit: it
 * cannot fix code that is not broken, so it will retry, rewrite around the
 * detector, or — the realistic outcome — the human removes the guard from the
 * client config. A guard that gets switched off protects nothing, so its
 * false-positive budget is a security parameter and not a UX one.
 *
 * Medium and below are still REPORTED on the allow path. Not blocking is not
 * the same as not saying.
 */
export const BLOCK_AT: Severity = 'high';

/**
 * The scan, as a value, so the fail-closed path can be exercised.
 *
 * ★ THIS SEAM EXISTS FOR EXACTLY ONE REASON and it is worth defending, because
 * "injectable dependency" is normally how a PoC grows a configuration system.
 * The fail-closed branch below is the one branch that NO input can reach: the
 * engine is deliberately hard to make throw, so an assertion guarding that
 * branch, written against real input, would be an assertion that cannot fail.
 * This repository has shipped one of those before. Substituting a throwing scan
 * is the only way to make "a scan that throws refuses the write" a falsifiable
 * claim, so the seam is here, unexported from the package index, and used by
 * nothing but the test.
 */
export type ScanFn = (request: ScanRequest, options?: AnalyzerOptions) => ScanResponse;

/** Why a write was refused. The agent's next move differs per case. */
export type RefusalReason =
  /** The content carries at least one finding at or above `BLOCK_AT`. Fixable. */
  | 'findings'
  /** The scan threw. Not fixable by editing the content — see fail-closed below. */
  | 'scan-failed'
  /** The content exceeds `MAX_FILE_BYTES`, so it was never scanned. */
  | 'too-large'
  /** `path` or `content` was missing or not a string. A caller bug. */
  | 'invalid-arguments';

export interface Verdict {
  decision: 'allow' | 'refuse';
  /** Present iff `decision === 'refuse'`. */
  reason?: RefusalReason;
  /** Echoed back so a multi-file agent can correlate. Never used to touch disk. */
  path: string;
  /** What `detectLanguageFromPath` made of `path`; absent for unknown extensions. */
  language?: string;
  /** Findings at or above `BLOCK_AT`. Empty on every allow. */
  blocking: Finding[];
  /** Every finding, including the below-threshold ones that did not block. */
  observed: Finding[];
  /** Bounds the scan hit. An allow carrying these saw only part of the input. */
  degradations: ScanDegradation[];
  /** One line naming the decision and its cause, for a human reading a log. */
  detail: string;
}

/**
 * The shape `adjudicate` wants — and NOT its parameter type, which is
 * `unknown`. The value arrives off a wire, produced by a language model; typing
 * the parameter as this interface would mean the compiler asserting a
 * guarantee nothing checks, and the first malformed call would reach the
 * validation code as a lie the type system had already signed off on. So the
 * interface documents the contract and the function verifies it.
 */
export interface AdjudicateInput {
  path: string;
  content: string;
}

/**
 * `Buffer.byteLength` rather than `content.length`.
 *
 * `MAX_FILE_BYTES` is a BYTE cap — `file-scanner.ts` compares it against
 * `stat().size` — and a JS string length is UTF-16 code units. For a file of
 * CJK text or emoji the two differ by up to 3x, so using `.length` here would
 * admit content the CLI would have skipped and would make the two channels
 * disagree about the same file. Reusing the project's constant is only worth
 * anything if it is also reused with the project's unit.
 */
function byteLength(content: string): number {
  return Buffer.byteLength(content, 'utf8');
}

function refuse(
  reason: RefusalReason,
  path: string,
  detail: string,
  extra?: Partial<Verdict>,
): Verdict {
  return {
    decision: 'refuse',
    reason,
    path,
    blocking: [],
    observed: [],
    degradations: [],
    detail,
    ...extra,
  };
}

/**
 * Decide whether `content` may be written to `path`.
 *
 * Pure. No filesystem access, no network, no clock-dependent branch. The whole
 * point of the header argument above is that this signature is the product.
 */
export function adjudicate(input: unknown, scanFn: ScanFn = coreScan): Verdict {
  // ── Argument validation is a REFUSAL, not a thrown error ─────────────────
  //
  // These arguments are produced by a language model, not by a programmer, so
  // "the call was malformed" is a thing the model must see and correct — and
  // the surest way to put it in front of the model is the tool result it is
  // already reading, rather than a JSON-RPC error object that some clients log
  // and never surface. It is also fail-closed for free: an argument shape this
  // code does not understand cannot end up allowed.
  const args = input as Partial<AdjudicateInput> | null | undefined;
  const path = typeof args?.path === 'string' ? args.path : '';
  if (path === '') {
    return refuse(
      'invalid-arguments',
      path,
      'refused: "path" is required and must be a non-empty string. It is used only to ' +
        'detect the language and to label the verdict; no file is opened.',
    );
  }
  if (typeof args?.content !== 'string') {
    return refuse(
      'invalid-arguments',
      path,
      'refused: "content" is required and must be a string — the FULL text you intend ' +
        'the file to have, not a patch or a diff.',
    );
  }
  const content = args.content;

  // ── The size cap: the project's number, deliberately NOT the project's response
  //
  // `MAX_FILE_BYTES` is imported rather than redefined so that "too big to
  // scan" means one thing across the product. What differs is what happens
  // next, and the difference is forced by the direction of the failure:
  // `scanPath` SKIPS an oversized file, which is right for a review-time sweep
  // (the file is on disk either way, the report is visibly partial, and a human
  // can open it). Skipping here would mean unscanned content landing under a
  // green light, which is the definition of failing open. So the same threshold
  // produces the opposite action, and the reason is that this caller's "no
  // answer" is a permission rather than a gap in a report.
  const bytes = byteLength(content);
  if (bytes > MAX_FILE_BYTES) {
    return refuse(
      'too-large',
      path,
      `refused: ${bytes} bytes exceeds the ${MAX_FILE_BYTES}-byte scan limit, so this ` +
        'content was NOT analysed. Split the file, or write it through a channel that ' +
        'accepts an unscanned write — this guard does not grant one.',
    );
  }

  const language = detectLanguageFromPath(path);

  // ── Fail CLOSED ──────────────────────────────────────────────────────────
  //
  // If the scan throws, the write is refused.
  //
  // The argument is about what TRUST does to a failure. An unguarded agent
  // writing insecure code is a known risk that a reviewer is looking for. A
  // GUARDED agent writing insecure code is worse, because the guard's existence
  // is why nobody is looking: the reviewer, the CI config, and the human's
  // attention have all been reallocated on the strength of it. A guard that
  // answers "allowed" when it did not run therefore does not merely fail to
  // help — it converts a visible risk into an invisible one, and it does so
  // silently, because "allowed because clean" and "allowed because the scanner
  // crashed" are the same two bytes on the wire.
  //
  // Refusing is the recoverable direction. It is loud, it stops exactly one
  // write, and both the agent and the human find out immediately. The
  // asymmetry is the entire argument: a wrong refusal costs a retry, a wrong
  // allow costs the thing this package exists to prevent.
  //
  // The reason is reported as `scan-failed` and NOT as `findings`, because the
  // two demand opposite responses from the agent. "Fix your code and retry" is
  // wrong advice for a crashed scanner: the agent would edit correct code,
  // retry, crash again, and loop. `scan-failed` says the guard is broken, which
  // is a human's problem.
  let result: ScanResponse;
  try {
    result = scanFn({
      targetType: 'file',
      content,
      filePath: path,
      language,
      // `standard`, not `fast`. `fast` filters the RULE SET down to
      // critical/high rules (see `filterRulesByMode`), which happens to be
      // exactly the blocking band — so it would be the cheaper way to compute
      // the same verdict. It is rejected because it would also make the allow
      // path a lie: "allowed, no findings" would mean "no critical/high RULE
      // ran and matched", and the medium/low findings this tool reports on the
      // way past would silently not exist. The blocking decision must be made
      // by the threshold below, visibly, rather than smuggled into rule
      // selection where no reader of this file would see it.
      mode: 'standard',
      includeRemediation: true,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return refuse(
      'scan-failed',
      path,
      `refused: the VibeGuard scan itself failed (${message}). This guard fails CLOSED — ` +
        'it will not approve content it did not analyse. Do not edit the content in ' +
        'response to this; report the scanner failure.',
      { language },
    );
  }

  const observed = result.findings;
  const blocking = observed.filter((f) => compareSeverity(f.severity, BLOCK_AT) <= 0);
  // `degradations` is optional on the response and present only when non-empty.
  const degradations = result.degradations ?? [];

  if (blocking.length > 0) {
    return {
      decision: 'refuse',
      reason: 'findings',
      path,
      ...(language === undefined ? {} : { language }),
      blocking,
      observed,
      degradations,
      detail: `refused: ${blocking.length} finding(s) at ${BLOCK_AT} or above.`,
    };
  }

  // ── The known fail-open seam, named rather than hidden ───────────────────
  //
  // A `ScanDegradation` means the scan RAN but did not see everything — a rule
  // hit `REGEX_INPUT_CAP` (50,000 chars, well under `MAX_FILE_BYTES`), the
  // scan-wide deadline, or the per-file match ceiling. Strictly, fail-closed
  // reasoning says refuse: an allow over a partial scan is a claim about text
  // that was never read.
  //
  // It allows anyway, and the reason is that refusing would make the guard
  // useless on precisely the files agents generate most — anything past 50 KB
  // would become unwritable, forever, with no edit that fixes it, because the
  // cause is a performance bound and not the content. The agent cannot repair a
  // deadline; it would retry identically until someone removed the guard. Per
  // the false-positive argument on `BLOCK_AT`, a guard that gets switched off
  // protects nothing.
  //
  // So the degradation rides along on the verdict and is rendered on the allow
  // line, which makes the partial scan visible to the human and to the model
  // without making the file unwritable. This is a WEAKER position than the
  // fail-closed rule above, it is the honest one for a PoC, and it is listed in
  // the README's limitations rather than averaged into the pitch.
  return {
    decision: 'allow',
    path,
    ...(language === undefined ? {} : { language }),
    blocking: [],
    observed,
    degradations,
    detail:
      observed.length === 0
        ? 'allowed: no findings.'
        : `allowed: ${observed.length} finding(s), all below ${BLOCK_AT}.`,
  };
}

function renderFinding(f: Finding): string {
  const where = f.startLine === undefined ? '' : `:${f.startLine}`;
  const how = f.remediation?.how ? `\n      fix: ${f.remediation.how}` : '';
  const evidence = f.snippet ? `\n      at:  ${f.snippet.trim()}` : '';
  return `  - ${f.ruleId} [${f.severity}/${f.confidence}] ${f.title}\n` +
    `      ${f.filePath ?? ''}${where}${evidence}${how}`;
}

/**
 * The verdict as the text an MCP client hands to the model.
 *
 * Prose, not JSON, and the choice is about the reader. The consumer is a
 * language model deciding what to do next, and the thing it must extract is
 * "you were refused, here is the rule, here is the line, here is the fix" —
 * which is a sentence, not a schema. A JSON blob would additionally invite the
 * model to reproduce it, and a model echoing a findings object back into a
 * source file is a way to get the finding written into the code as a comment.
 *
 * The one structural commitment is the FIRST LINE: it starts with `REFUSED` or
 * `ALLOWED` so that a client truncating the result, or a human skimming a log,
 * gets the verdict before anything else. Every finding line carries its rule id
 * so the agent can name what it fixed on the retry.
 */
export function renderVerdict(v: Verdict): string {
  const head =
    v.decision === 'refuse'
      ? `REFUSED (${v.reason}) — ${v.path}\n${v.detail}`
      : `ALLOWED — ${v.path}\n${v.detail}`;

  const parts = [head];

  if (v.blocking.length > 0) {
    parts.push(`\nBlocking findings:\n${v.blocking.map(renderFinding).join('\n')}`);
  }
  const belowThreshold = v.observed.filter((f) => !v.blocking.includes(f));
  if (belowThreshold.length > 0) {
    parts.push(
      `\nNot blocking (below ${BLOCK_AT}), reported for information:\n` +
        belowThreshold.map(renderFinding).join('\n'),
    );
  }
  if (v.degradations.length > 0) {
    parts.push(
      '\n★ This scan was PARTIAL — it did not read all of the content:\n' +
        v.degradations.map((d) => `  - ${d.ruleId} [${d.kind}] ${d.detail}`).join('\n'),
    );
  }
  if (v.decision === 'refuse' && v.reason === 'findings') {
    parts.push(
      '\nThe file was NOT written — nothing was written, because this tool never writes. ' +
        'Fix the findings above and call this tool again with the corrected content.',
    );
  } else if (v.decision === 'allow') {
    parts.push(
      '\nNothing was written: this tool only adjudicates. Perform the write with your own ' +
        'file-writing tool.',
    );
  }

  return parts.join('\n');
}
