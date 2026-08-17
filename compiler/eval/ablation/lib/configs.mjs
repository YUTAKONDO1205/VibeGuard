// The six components of the design plan section 24 and the nine configurations A–I built from them.
//
// §24 names the configurations by the components they switch on; it does not
// say which directory each component is. That mapping is a claim about this
// repository and is written here, once, so that a reader can disagree with it
// in one place rather than in nine.
//
// Two of the mappings are worth arguing about and are argued about in README.md:
// the Source Gate is the shipped analyser rather than anything under compiler/,
// and Object/Link Integrity is two components (elf-verifier and link-wrapper)
// that answer different questions from each other.

export const COMPONENTS = {
  sourceGate: {
    id: 'sourceGate',
    label: 'Source Gate',
    implementedBy: 'apps/cli/dist/index.js (shipped VibeGuard analyser)',
    question: 'does the source text state the property at all?',
  },
  astGate: {
    id: 'astGate',
    label: 'AST Gate',
    implementedBy: 'compiler/clang-plugin (IntentGate)',
    question: 'does the AST agree that this location denotes the effect?',
  },
  irPrePost: {
    id: 'irPrePost',
    label: 'Pre/Post IR comparison',
    implementedBy: 'compiler/llvm-pass (IrCheckpoints); measured here through the shared predicate at ir-pre and ir-post',
    question: 'was the effect in the IR before the optimiser and gone after it?',
  },
  passTracking: {
    id: 'passTracking',
    label: 'Pass-Level Tracking',
    implementedBy: 'compiler/pass-instrumentation/observer (PropertyObserver)',
    question: 'which pass, on which IR unit, removed it?',
  },
  objectLink: {
    id: 'objectLink',
    label: 'Object/Link Integrity',
    implementedBy: 'compiler/elf-verifier + compiler/link-wrapper',
    question: 'does the linked artefact still contain the effect, and only what was asked for?',
  },
  evidenceVerifier: {
    id: 'evidenceVerifier',
    label: 'Evidence Verifier',
    // Named by path at run time (`--verifier`) rather than here. Writing a
    // filename into this record would state which file was driven, and this
    // field is copied into the output whether or not that file was the one
    // found — which is how a run that drove nothing kept describing what it
    // drove. The path actually resolved is recorded in
    // `binaries.evidenceVerifier`, beside whether it was there.
    implementedBy: 'the evidence verifier in the measurement workspace, given by --verifier (an independent reimplementation of evidence-v0)',
    question: 'is the record of the run the record its signer sealed?',
  },
};

// §24 verbatim. Note that the AST Gate appears in no combination: B is the only
// configuration that contains it. That is §24's shape, not an omission here.
export const CONFIGURATIONS = {
  A: { label: 'Source Gate only', components: ['sourceGate'] },
  B: { label: 'AST Gate only', components: ['astGate'] },
  C: { label: 'Pre-Post IR comparison only', components: ['irPrePost'] },
  D: { label: 'Pass-Level Tracking only', components: ['passTracking'] },
  E: { label: 'Object-Link Integrity only', components: ['objectLink'] },
  F: { label: 'Evidence Verifier only', components: ['evidenceVerifier'] },
  G: { label: 'A + C', components: ['sourceGate', 'irPrePost'] },
  H: { label: 'A + C + D', components: ['sourceGate', 'irPrePost', 'passTracking'] },
  I: {
    label: 'A + C + D + E + F',
    components: ['sourceGate', 'irPrePost', 'passTracking', 'objectLink', 'evidenceVerifier'],
  },
};

/**
 * The vocabulary a gate may return for one cell. Kept apart from the property
 * states in compiler/schema/interfaces.md §3 on purpose: these are statements
 * about the *gate*, not about the property.
 *
 *   DETECTED               the gate reported the loss
 *   NOT_DETECTED           the gate ran, completed, and reported nothing
 *   NOT_APPLICABLE         the gate answers a different question about this
 *                          property; there is no way for it to detect this loss
 *                          and calling that a miss would be a category error
 *   UNSUPPORTED            the gate cannot be run on this cell at all, e.g. no
 *                          rule in its table targets this property
 *   VERIFICATION_INCOMPLETE the gate ran and its own validity check failed —
 *                          a blind oracle, an unresolved subject, a missing log.
 *                          Never merged into NOT_DETECTED.
 *   NOT_OBSERVED           the gate was not run in this invocation
 */
export const GATE_RESULTS = [
  'DETECTED',
  'NOT_DETECTED',
  'NOT_APPLICABLE',
  'UNSUPPORTED',
  'VERIFICATION_INCOMPLETE',
  'NOT_OBSERVED',
];

/**
 * Combine per-component results into one configuration result.
 *
 * A union, with two rules that are not a union:
 *   - one DETECTED wins, because a configuration detects what any of its
 *     components detects;
 *   - otherwise the *weakest* honest word survives, so a configuration whose
 *     only running component could not validate its own oracle does not report
 *     a clean NOT_DETECTED.
 */
export function combine(results) {
  const vals = Object.values(results);
  if (vals.includes('DETECTED')) return 'DETECTED';
  if (vals.includes('NOT_DETECTED')) return 'NOT_DETECTED';
  if (vals.includes('VERIFICATION_INCOMPLETE')) return 'VERIFICATION_INCOMPLETE';
  if (vals.includes('UNSUPPORTED')) return 'UNSUPPORTED';
  if (vals.includes('NOT_APPLICABLE')) return 'NOT_APPLICABLE';
  return 'NOT_OBSERVED';
}
