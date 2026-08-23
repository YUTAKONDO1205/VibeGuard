// Cross-examining claims about protections.
//
// ── THE RULE ────────────────────────────────────────────────────────────────
//
// A claim that a protection exists is an accusation, not evidence. Whoever made
// it — a rule reading the source, a fixer reporting its own edit, a coding
// assistant describing what it wrote — has created something that must be
// proven and has proven nothing. So a claim is born `NOT_OBSERVED`, and only an
// observation at a layer OTHER than the claimant's may move it.
//
// The consequence that shapes every function here: a claim can only ever ADD
// something to prove. It cannot turn a screen green. That is not a stylistic
// preference. The obvious alternative design — let the assistant annotate its
// output and believe the annotation — makes the party under examination the
// examiner, and the whole reason this product exists is that its user cannot
// check the assistant's word. A green tick sourced from that word hands the
// user back precisely the question they could not answer.
//
// ── WHAT THE LAYERS ARE ─────────────────────────────────────────────────────
//
//   assistant  the prose a coding assistant wrote next to the code
//   source     the source text, as read by a rule
//   fixer      a fixer's record of what it inserted
//   artifact   the bytes the project ships
//   sidecar    a file shipped alongside — a source map
//
// The first three make claims. The last two settle them. Nothing settles a
// claim made at its own layer, and `illegalClaimTransition` in
// `@vibeguard/findings-schema` is the single place that rule is written down.

/**
 * Rules whose findings are claims about a protection that a build can remove.
 *
 * Only these become claims. A finding that SQL is being concatenated is not a
 * claim that a protection exists — it is the opposite — and feeding it into
 * this channel would produce a "protection" whose disappearance is good news.
 *
 * `witness` says how to pull the checkable token out of the finding's evidence.
 * A finding whose witness cannot be extracted still becomes a claim: it simply
 * can never leave `NOT_OBSERVED`, and saying so is more useful than dropping it,
 * because the claimant has already told the user the protection is there.
 */
export const CLAIM_BEARING_RULES = Object.freeze({
  'VG-AUTH-009': {
    subject: 'an authorization check that only runs in development',
    witness: identifierWitness,
  },
  'VG-AUTH-010': {
    subject: 'an authorization check written as console.assert',
    witness: identifierWitness,
  },
  'VG-AUTH-011': {
    subject: 'an authorization check written as a Python assert',
    witness: identifierWitness,
  },
  'VG-AUTH-008': {
    subject: 'an authorization check written as a C assert',
    witness: identifierWitness,
  },
  'VG-MEM-006': {
    subject: 'a secret being wiped before it goes out of scope',
    witness: identifierWitness,
  },
});

/**
 * Pull the most specific identifier out of a finding's evidence.
 *
 * Deliberately simple, and deliberately biased towards returning nothing: a
 * wrong witness produces a confident wrong verdict, while no witness produces
 * `NOT_OBSERVED`, which is true. So this takes the longest identifier-shaped
 * run that is not a language keyword, and returns null when there is no clear
 * winner.
 */
export function identifierWitness(evidence) {
  const KEYWORDS = new Set([
    'if', 'else', 'return', 'throw', 'new', 'Error', 'const', 'let', 'var',
    'function', 'assert', 'console', 'process', 'env', 'true', 'false', 'null',
    'undefined', 'typeof', 'await', 'async', 'this', 'not', 'and', 'or',
    'production', 'development', 'NODE_ENV', 'raise', 'def', 'import',
  ]);
  const admissible = (s) => !KEYWORDS.has(s) && s.length >= 4;

  // ── PROPERTY NAMES FIRST, AND NOT AS A TIE-BREAK ──────────────────────────
  //
  // A witness is only useful if it would still be spelled the same way in the
  // shipped bytes, and minifiers treat the two kinds of name completely
  // differently. A local or a parameter is renamed — `session` becomes `s` —
  // because the minifier can see every use. A property read through a dot is
  // NOT renamed, because it cannot know who else indexes the object; that is
  // why `--mangle-props` exists as a separate, opt-in, widely-avoided flag.
  //
  // So `session.isAdmin` has exactly one usable witness and it is `isAdmin`.
  // The first version of this function took the longest identifier, which on
  // that expression is a tie that `session` wins by position — a witness
  // guaranteed to be absent from any minified artefact, which would have made
  // every claim read LOST. Caught by `cross-examine.test.mjs` rather than in
  // the field, and worth stating plainly: the earlier heuristic did not
  // produce a slightly worse witness, it produced a systematically wrong one.
  const props = (evidence.match(/\.([A-Za-z_$][A-Za-z0-9_$]{2,})/g) ?? [])
    .map((s) => s.slice(1))
    .filter(admissible);
  const pick = (xs) => {
    let best = null;
    for (const x of xs) if (best === null || x.length > best.length) best = x;
    return best;
  };
  const fromProps = pick(props);
  if (fromProps) return fromProps;

  // No property access. Fall back to a bare identifier — a called function
  // name such as `is_admin(u)` survives minification for the same reason a
  // property does when it is imported or global, and a renamed local simply
  // yields a claim that reads LOST, which is the visible direction.
  return pick((evidence.match(/[A-Za-z_$][A-Za-z0-9_$]{2,}/g) ?? []).filter(admissible));
}

/**
 * Turn source-layer findings into claims.
 *
 * Every returned claim has `state: 'NOT_OBSERVED'` and no `crossExaminedAt`.
 * That is the invariant, and it holds unconditionally here: this function has
 * no access to an artefact and therefore has nothing that could settle
 * anything.
 */
export function claimsFromFindings(findings) {
  const out = [];
  let n = 0;
  for (const f of findings) {
    const spec = CLAIM_BEARING_RULES[f.ruleId];
    if (!spec) continue;
    // `Finding.evidence` is an array of lines and `snippet` is the matched
    // source line; either can carry the identifier, and neither is guaranteed.
    // Joined rather than chosen between, because a witness that appears in one
    // and not the other is still a witness, and picking the wrong field is how
    // a claim silently loses the only token that could settle it.
    const text = [f.snippet ?? '', ...(f.evidence ?? [])].join('\n').trim();
    const witness = text ? spec.witness(text) : null;
    out.push({
      id: `claim-${++n}`,
      claimant: f.ruleId,
      claimantLayer: 'source',
      subject: spec.subject,
      ...(witness ? { witness } : {}),
      ...(f.filePath ? { filePath: f.filePath } : {}),
      ...(f.startLine ? { startLine: f.startLine } : {}),
      state: 'NOT_OBSERVED',
    });
  }
  return out;
}

/**
 * Turn a coding assistant's prose into claims.
 *
 * ── WHY A REGEX AND NOT A MODEL ─────────────────────────────────────────────
 *
 * There is published work that does this conversion properly with a language
 * model, and it does it better than what is below. This package cannot call
 * one: nothing here touches the network, which is the promise the product is
 * built on, and a claim extractor that phones out would break it for every
 * user in order to improve one channel.
 *
 * That constraint is survivable precisely because of the rule at the top of
 * this file. A missed claim costs a line of output nobody sees. A wrongly
 * extracted claim costs a line of output that says NOT_OBSERVED. Neither can
 * produce a false assurance, because no claim from this layer — however it was
 * extracted — is allowed to settle itself. The quality of this function bounds
 * how much work it creates, not how much it can mislead.
 */
export function claimsFromAssistantProse(prose, { filePath } = {}) {
  const out = [];
  let n = 0;
  // Sentence-ish segmentation. Assistant prose is bulleted as often as it is
  // written in sentences, so newlines and list markers split too.
  const segments = prose
    .split(/(?:[.!?]\s+|\n+|^\s*[-*]\s*)/m)
    .map((s) => s.trim())
    .filter((s) => s.length >= 12 && s.length <= 400);
  const ACTION =
    /\b(?:add(?:ed|ing)?|insert(?:ed)?|introduc(?:e|ed)|implement(?:ed)?|enforc(?:e|ed|ing)|check(?:ed|ing)?|validat(?:e|ed|ing|ion)|sanitiz(?:e|ed)|sanitis(?:e|ed)|escap(?:e|ed)|wipe[ds]?|zero(?:ed|ing)?|clear(?:ed)?|guard(?:ed)?|restrict(?:ed)?|requir(?:e|ed|es))\b/i;
  const SUBJECT =
    /\b(?:auth(?:z|entication|orization|orisation)?|permission|privilege|admin|role|access control|input validation|sanitis|sanitiz|escap|csrf|xss|injection|secret|credential|token|password|rate limit)\w*/i;
  for (const seg of segments) {
    if (!ACTION.test(seg)) continue;
    const subjectMatch = seg.match(SUBJECT);
    if (!subjectMatch) continue;
    const witness = identifierWitness(seg);
    out.push({
      id: `assistant-claim-${++n}`,
      claimant: 'assistant',
      claimantLayer: 'assistant',
      subject: seg.length > 140 ? `${seg.slice(0, 137)}…` : seg,
      ...(witness ? { witness } : {}),
      ...(filePath ? { filePath } : {}),
      // Unconditional. See the rule at the top of this file.
      state: 'NOT_OBSERVED',
    });
  }
  return out;
}

/**
 * Settle claims against an artefact observation.
 *
 * `observation` is the return of `observeBundleDir`. `illegal` is the
 * transition guard from `@vibeguard/findings-schema`, injected rather than
 * imported so this Node-only module does not pull a browser-bundled package
 * into its own dependency list; the caller passes
 * `illegalClaimTransition`.
 *
 * A claim is settled only if:
 *   * it has a witness (nothing to look for means nothing to find), AND
 *   * at least one artefact record held its control (a measurement with a dead
 *     control is broken, not clean), AND
 *   * the transition is legal for the claim's own layer.
 *
 * Anything else stays `NOT_OBSERVED` with the reason recorded.
 */
export function crossExamine(claims, observation, illegal) {
  const usable = observation.records.filter((r) => r.controlHeld);
  return claims.map((claim) => {
    if (!claim.witness) {
      return { ...claim, state: 'NOT_OBSERVED', note: 'the claim names nothing that can be looked for in the shipped bytes' };
    }
    if (!usable.length) {
      return { ...claim, state: 'NOT_OBSERVED', note: 'no artefact in the build output could be measured with a live control' };
    }
    let inCode = false;
    let inSidecar = false;
    let where = null;
    for (const r of usable) {
      for (const w of r.witnesses) {
        if (w.witness !== claim.witness) continue;
        if (w.inCode) {
          inCode = true;
          where = r.artefact;
        }
        if (w.inSidecar) {
          inSidecar = true;
          where = where ?? r.artefact;
        }
      }
    }
    const observedAt = inSidecar && !inCode ? 'sidecar' : 'artifact';
    const next = inCode ? 'PRESENT' : inSidecar ? 'REINTRODUCED' : 'LOST';
    const reason = illegal(claim, observedAt, next);
    if (reason) {
      // Cannot happen for the claimant layers this package produces, and is
      // checked anyway: the day somebody adds an artefact-layer claimant, this
      // is the line that stops it grading its own homework.
      return { ...claim, state: 'NOT_OBSERVED', note: reason };
    }
    const note =
      next === 'PRESENT'
        ? `found in ${where}`
        : next === 'REINTRODUCED'
          ? `absent from the code that runs, still published in the source map next to ${where}`
          : `not found in any measured artefact under the build output`;
    return { ...claim, state: next, crossExaminedAt: observedAt, note };
  });
}
