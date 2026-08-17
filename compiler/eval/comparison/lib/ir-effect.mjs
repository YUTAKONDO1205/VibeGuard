// Arm 7: count effect call sites at the two endpoints of the pipeline.
//
// This is the deliberately weak sibling of the pass-level arm. It sees printed
// .ll at two moments and nothing in between, and it matches callees by name in
// text rather than by resolved callee on a CallBase. Both limitations are real
// and both are the point of the comparison, so neither is papered over -- but
// the one failure mode that would make the arm *lie* is fenced:
//
//   a function that is not in the module must come back NOT_OBSERVED, never
//   LOST. "I could not find the subject" and "the subject's defence is gone"
//   are the same shape to a careless counter, and only one of them is a
//   finding.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

/**
 * Slice the body of one `define` out of printed LLVM IR.
 *
 * Returns null when the module has no definition of that name -- which is a
 * different answer from an empty body, and the caller must treat it as one.
 */
export function functionBody(llText, fnName) {
  const lines = llText.split('\n');
  // `define ... @name(` -- the paren is required so that @process does not
  // match @process_control.
  const open = new RegExp(`^define\\b.*@"?${escapeRe(fnName)}"?\\(`);
  let start = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (open.test(lines[i])) { start = i; break; }
  }
  if (start === -1) return null;
  for (let i = start; i < lines.length; i += 1) {
    if (lines[i] === '}') return lines.slice(start, i + 1).join('\n');
  }
  return lines.slice(start).join('\n');
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/**
 * Count call sites in `body` whose callee name matches one of `symbols`.
 *
 * The name must be followed by `(` or `.`, so that `@memset` matches
 * `@memset(` and `@llvm.memset.p0.i64(` matches the symbol `llvm.memset`,
 * while `@memset_chk(` matches neither. A bare `declare` is not counted: only
 * lines carrying `call` or `invoke` are considered, because a leftover
 * declaration is what a name search mistakes for a live call.
 */
export function countEffectCalls(body, symbols) {
  const hits = [];
  for (const raw of body.split('\n')) {
    const line = raw.trim();
    if (!/\b(call|invoke)\b/.test(line)) continue;
    for (const sym of symbols) {
      const re = new RegExp(`@"?${escapeRe(sym)}"?(\\(|\\.)`);
      if (re.test(line)) { hits.push({ symbol: sym, line }); break; }
    }
  }
  return hits;
}

/**
 * Endpoint comparison for one function.
 *
 * `state` is PRESENT / LOST / NOT_OBSERVED. NOT_OBSERVED covers both "the
 * function is not in the pre-optimisation module" (a bad configuration, or a
 * defence the preprocessor already removed) and "the function is gone from the
 * post module" -- the second is reported as a fate, not as a property loss,
 * for the same reason the observer keeps those on separate channels.
 */
export function endpointCompare(preText, postText, fnName, symbols) {
  const preBody = functionBody(preText, fnName);
  if (preBody === null) {
    return {
      state: 'NOT_OBSERVED',
      attribution: 'NOT_OBSERVED',
      reason:
        `'${fnName}' is not defined in the pre-optimisation module. `
        + 'Nothing in this cell is an observation of it; this is not a loss.',
      preCount: null,
      postCount: null,
      fate: null,
    };
  }
  const preHits = countEffectCalls(preBody, symbols);
  const postBody = functionBody(postText, fnName);
  if (postBody === null) {
    return {
      state: 'NOT_OBSERVED',
      attribution: 'NOT_OBSERVED',
      reason:
        `'${fnName}' is defined before the pipeline and absent after it. `
        + 'The unit disappeared; that is a fate, not a property state, and '
        + 'this arm cannot tell which of the two the caller cares about.',
      preCount: preHits.length,
      postCount: null,
      fate: 'ERASED_OR_INLINED',
    };
  }
  const postHits = countEffectCalls(postBody, symbols);
  // interfaces.md §3 vocabulary. The three cases are genuinely different:
  //   PRESENT  the effect is in the post-pipeline IR
  //   LOST     it was in the pre IR and is not in the post IR
  //   ABSENT   it was in neither -- "observed to be missing, at a point where
  //            the property had not yet been established". The function exists
  //            and was read; the effect simply never entered the IR, which is
  //            what a preprocessor-stage removal looks like from here. Calling
  //            this NOT_OBSERVED would understate it (the arm did observe), and
  //            calling it LOST would blame the optimiser for something it never
  //            saw.
  let state;
  if (postHits.length > 0) state = 'PRESENT';
  else if (preHits.length > 0) state = 'LOST';
  else state = 'ABSENT';
  return {
    state,
    attribution: state === 'ABSENT' ? 'LOSS_PRECEDES_WINDOW' : 'NO_ATTRIBUTION_BY_DESIGN',
    reason: state === 'ABSENT'
      ? `no call to any of [${symbols.join(', ')}] in '${fnName}' at either endpoint. `
        + 'The function was found and read at both endpoints, so this is an '
        + 'observation, not a miss: the effect was never in the IR, and nothing '
        + 'in the pass pipeline can be responsible for its absence.'
      : null,
    preCount: preHits.length,
    postCount: postHits.length,
    preSymbols: [...new Set(preHits.map((h) => h.symbol))],
    postSymbols: [...new Set(postHits.map((h) => h.symbol))],
    fate: 'LIVE',
  };
}
