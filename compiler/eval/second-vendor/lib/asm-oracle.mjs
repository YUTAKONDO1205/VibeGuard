/**
 * Vendor-neutral assembly oracle.
 *
 * The whole point of this file is that the SAME code reads clang output and gcc
 * output. Anything that only works for one vendor belongs in a comment, not in a
 * branch, because a per-vendor branch is how a comparison quietly stops being a
 * comparison.
 *
 * Vocabulary is load-bearing and must not be collapsed:
 *   PRESENT       - the effect was observed in the target function body
 *   ABSENT        - the function body was read, and the effect was not in it
 *   NOT_OBSERVED  - the function body could not be read at all (nothing to say)
 */

/** Strip an assembler line comment while leaving string literals alone enough for our purposes. */
function stripComment(line) {
  // clang appends "# @fn"; gcc uses "#" too. ";" and "//" are not used by either
  // of these two on x86-64 ELF, so "#" is sufficient here.
  const i = line.indexOf('#');
  return (i === -1 ? line : line.slice(0, i)).trimEnd();
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Extract the body of `fnName` from assembly text.
 *
 * Start: a line beginning at column 0 with `fnName:`.
 * End:   the `.size fnName, ...` directive that closes it.
 *
 * Both clang and gcc emit both markers for a global function on ELF. If the
 * closing `.size` is missing we refuse to guess a boundary and return null,
 * because a wrong boundary silently imports a neighbouring function's calls.
 *
 * Exact-name matching matters: `handle_request` is a prefix of
 * `handle_request_bzero`, and `verify_user` is a prefix of `verify_user_control`.
 *
 * @returns {{lines: string[], startLine: number, endLine: number} | null}
 */
export function extractFunctionBody(asmText, fnName) {
  const lines = asmText.split('\n');
  const startRe = new RegExp('^' + escapeRe(fnName) + ':');
  const endRe = new RegExp('^\\s*\\.size\\s+' + escapeRe(fnName) + '\\s*,');

  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (startRe.test(lines[i])) { start = i; break; }
  }
  if (start === -1) return null;

  for (let j = start + 1; j < lines.length; j++) {
    if (endRe.test(lines[j])) {
      return { lines: lines.slice(start, j + 1), startLine: start + 1, endLine: j + 1 };
    }
  }
  return null;
}

/**
 * Find transfers of control to any of `symbols` inside a function body.
 *
 * Matches BOTH the ordinary call and the tail call. gcc at -O2 emits
 * `jmp report_denied@PLT` for a tail-called reporter; a detector that only
 * looked for `call` would have declared that defence LOST when it is plainly
 * present. That mistake was observed on this fixture set before this branch
 * existed, which is why the jmp form is here.
 */
export function detectCallLike(bodyLines, symbols) {
  const evidence = [];
  const alternation = symbols.map(escapeRe).join('|');
  // Anchored at end of (comment-stripped) line so that `verify_user@PLT` does
  // not match when the operand is really `verify_user_control@PLT`.
  const re = new RegExp('^\\s*(call|callq|jmp|jmpq)\\s+(' + alternation + ')(@PLT)?\\s*$');
  for (const raw of bodyLines) {
    const line = stripComment(raw);
    const m = re.exec(line);
    if (m) evidence.push({ kind: 'call-like', mnemonic: m[1], symbol: m[2], line: line.trim() });
  }
  return evidence;
}

/**
 * Find an inlined zeroing of stack memory.
 *
 * At -O1 and above neither vendor necessarily keeps a `memset` call: clang emits
 * `xorps %xmm0,%xmm0` + `movaps %xmm0,(%rsp)`, gcc emits `pxor %xmm0,%xmm0` +
 * `movaps %xmm0,(%rsp)`. Both are the wipe, in the form that configuration chose.
 * Only counting the call would report the surviving wipe as lost.
 *
 * Two idioms are recognised:
 *   1. a vector register zeroed against itself, then stored to a memory operand
 *   2. an immediate zero stored directly to a memory operand
 *
 * The destination must be a memory operand (it contains a parenthesised base).
 * `movl $0, %esi` is an argument setup, not a wipe, and must not count.
 */
export function detectInlineZeroStore(bodyLines) {
  const evidence = [];
  const zeroed = new Set();

  const selfXorRe = /^\s*(?:v)?(xorps|xorpd|pxor|pxord|pxorq)\s+%([xyz]mm\d+),\s*%([xyz]mm\d+)\s*$/;
  const vecStoreRe = /^\s*(?:v)?(movaps|movups|movapd|movupd|movdqa|movdqu)\s+%([xyz]mm\d+),\s*([^,]*\([^)]*\))\s*$/;
  const immStoreRe = /^\s*mov([bwlq])?\s+\$0\s*,\s*([^,]*\([^)]*\))\s*$/;
  // aarch64 zero-register pair store, harmless on x86-64 and correct if this
  // fixture set is ever run on arm64.
  const aarch64ZeroRe = /^\s*(stp|str)\s+(x|w)zr\s*,/;

  for (const raw of bodyLines) {
    const line = stripComment(raw);

    const sx = selfXorRe.exec(line);
    if (sx && sx[2] === sx[3]) { zeroed.add(sx[2]); continue; }

    const vs = vecStoreRe.exec(line);
    if (vs && zeroed.has(vs[2])) {
      evidence.push({ kind: 'inline-zero-store', form: 'vector', reg: vs[2], dest: vs[3], line: line.trim() });
      continue;
    }

    const is = immStoreRe.exec(line);
    if (is) {
      evidence.push({ kind: 'inline-zero-store', form: 'immediate', dest: is[2], line: line.trim() });
      continue;
    }

    if (aarch64ZeroRe.test(line)) {
      evidence.push({ kind: 'inline-zero-store', form: 'aarch64-zr', line: line.trim() });
    }
  }
  return evidence;
}

/**
 * Read one function and say whether the effect is there.
 *
 * @param {string} asmText   full assembly listing
 * @param {string} fnName    function to read
 * @param {{symbols: string[], allowInlineZeroStore: boolean}} effect
 * @returns {{verdict: 'PRESENT'|'ABSENT'|'NOT_OBSERVED', evidence: object[], reason: string|null, bodyLineCount: number|null}}
 */
export function observeEffect(asmText, fnName, effect) {
  const body = extractFunctionBody(asmText, fnName);
  if (!body) {
    return {
      verdict: 'NOT_OBSERVED',
      evidence: [],
      reason: 'function-body-not-delimited: no `' + fnName + ':` label with a closing `.size ' + fnName + ',` directive',
      bodyLineCount: null,
    };
  }
  const evidence = detectCallLike(body.lines, effect.symbols);
  if (effect.allowInlineZeroStore) evidence.push(...detectInlineZeroStore(body.lines));

  return {
    verdict: evidence.length > 0 ? 'PRESENT' : 'ABSENT',
    evidence,
    reason: null,
    bodyLineCount: body.lines.length,
  };
}

/**
 * Combine the subject reading and the positive-control reading into a cell state.
 *
 * The control exists so that "I did not see it" can be told apart from "I cannot
 * see anything". If the control is not PRESENT the oracle is blind in this
 * configuration and the cell is VERIFICATION_INCOMPLETE. Calling a blind cell
 * LOST is the single most attractive way to manufacture a result here.
 */
export function classifyCell(subject, control) {
  if (subject.verdict === 'NOT_OBSERVED') {
    return { state: 'NOT_OBSERVED', rationale: 'subject function could not be read: ' + subject.reason };
  }
  if (control.verdict !== 'PRESENT') {
    return {
      state: 'VERIFICATION_INCOMPLETE',
      rationale:
        'positive control did not show its effect (control verdict=' + control.verdict +
        '); the oracle is blind in this configuration, so the subject reading carries no information',
    };
  }
  if (subject.verdict === 'PRESENT') {
    return { state: 'PRESERVED', rationale: 'effect observed in subject; control also observed' };
  }
  return { state: 'LOST', rationale: 'effect absent from subject while control was observed in the same listing' };
}
