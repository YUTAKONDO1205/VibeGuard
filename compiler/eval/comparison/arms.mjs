// The nine systems of the design plan section 23.2, as a registry.
//
// Each arm declares three things, and the third is the one this lane exists
// for:
//
//   reports        what the arm's output actually contains
//   cannotReport   what its design cannot answer -- not a defect, a scope
//   verdictVocab   the words this arm is allowed to emit
//
// A comparison that only records `reports` degenerates into a league table, and
// a league table of tools that answer different questions is not a measurement.
// `cannotReport` is what keeps each row readable as "this is the question it
// was built for" rather than "this is how far down it came".
//
// Two arms do not run here, and they do not run for different reasons. Those
// reasons are carried in separate fields with separate codes, because
// collapsing them into one "unavailable" is exactly the kind of vocabulary loss
// that makes a result unreadable a month later:
//
//   TOOL_ABSENT     the arm is real and runnable in principle; this host does
//                   not have it installed. Ours to fix, not a property of the
//                   arm.
//   SUBJECT_ABSENT  there is no implementation to point the runner at. Nothing
//                   to install; the thing does not exist yet.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

// Two vocabularies, kept apart on purpose.
//
// The first is the property-state vocabulary of compiler/schema/interfaces.md
// §3 and is not extended here. Adding a synonym to it would be the exact
// failure that table's last two rows exist to prevent.
export const PROPERTY_STATES = Object.freeze([
  'PRESENT',        // the effect was observed at this point
  'ABSENT',         // observed missing where the property had not yet been established
  'LOST',           // observed missing where it had previously been PRESENT
  'REINTRODUCED',   // PRESENT again after being LOST
  'NOT_APPLICABLE', // the question lost its referent
  'NOT_OBSERVED',   // no observation was made here
]);

// The second says what happened to the *arm* in this cell, and never occupies
// a slot in the first. An arm that reported nothing about the property has not
// thereby said the property is absent.
export const ARM_STATUSES = Object.freeze([
  // The arm ran and reported successfully -- about a different question. A
  // scope statement, not a failure and not a low score.
  'OUT_OF_SCOPE',
  // The arm did not run. `unsupportedReason` says which kind, and the kinds
  // are not interchangeable.
  'UNSUPPORTED',
  // The arm ran, but a control that had to hold did not, so its answer about
  // the subject is not evidence in this cell.
  'VERIFICATION_INCOMPLETE',
  // The fixture declares no must-not-appear markers, so the arm's question has
  // no referent here. Different from scanning and finding nothing.
  'NO_MARKERS_DECLARED',
  // The fixture declares no IR-level property (role=artifact-only).
  'NO_PROPERTY_DECLARED',
]);

/** Attribution words. "No attribution" and "attribution not found" differ. */
export const ATTRIBUTION_VERDICTS = Object.freeze([
  // A named (pass, unit) pair.
  'ATTRIBUTED',
  // The arm can localise loss in the pipeline but found none, because the
  // property was still there at the end.
  'NO_LOSS_TO_ATTRIBUTE',
  // The arm reports whether, never where. Not a gap in the run -- a gap in
  // the arm's design, which is the whole point of comparing it with one that
  // does attribute.
  'NO_ATTRIBUTION_BY_DESIGN',
  // The loss happened outside the window this arm watches. Pass-level
  // instrumentation starts at the first IR boundary; a defence deleted by the
  // preprocessor was never in the IR to be removed from it.
  'LOSS_PRECEDES_WINDOW',
  'NOT_OBSERVED',
  'UNSUPPORTED',
]);

export const ARMS = [
  {
    id: 1,
    key: 'vibeguard-source',
    label: 'Current VibeGuard (source scanner)',
    status: 'runnable',
    layer: 'source',
    reports: [
      'rule hits on source constructs, with file/line, severity and confidence',
      'a remediation for each hit',
    ],
    cannotReport: [
      'whether the construct it flagged survived into the object file or the binary -- it never compiles anything',
      'anything that varies with -O level, -D macros or the compiler, because the same source text is its whole input',
      'which pass, if any, was responsible for a loss',
    ],
    verdictVocab: ['OUT_OF_SCOPE'],
    note:
      'Its answer to "is this risky source" is the answer it was built for. '
      + 'Recording it as OUT_OF_SCOPE on the survival question is a statement '
      + 'about the question, not about the tool.',
  },
  {
    id: 2,
    key: 'clang-static-analyzer',
    label: 'Clang Static Analyzer',
    status: 'runnable',
    layer: 'source/AST',
    reports: [
      'path-sensitive bug reports over the AST/CFG of one translation unit',
      'a diagnostic with a source location and an execution path',
    ],
    cannotReport: [
      'the effect of optimisation -- it runs on the frontend representation, before the pass pipeline exists',
      'whether a construct it accepted was later deleted by the optimiser',
      'anything about the linked artifact',
    ],
    verdictVocab: ['OUT_OF_SCOPE'],
    note:
      'It is preprocessor-sensitive (a -D flag changes what it sees) but not '
      + 'optimisation-sensitive. That split is measurable here and is recorded '
      + 'rather than asserted.',
  },
  {
    id: 3,
    key: 'clang-warnings',
    label: 'Clang warnings (-Wall -Wextra)',
    status: 'runnable',
    layer: 'source/AST',
    reports: [
      'frontend diagnostics, some of which are optimisation-informed at higher -O',
    ],
    cannotReport: [
      'a property state -- a warning is advice about code, not a claim that an effect is present or absent in the output',
      'which pass removed anything; warnings carry no pipeline position',
      'silence as safety: no warning is the overwhelmingly common case even when a defence has just been deleted',
    ],
    verdictVocab: ['OUT_OF_SCOPE'],
  },
  {
    id: 4,
    key: 'strings-scan',
    label: 'Binary strings scan',
    status: 'runnable',
    layer: 'artifact',
    reports: [
      'byte sequences present in the linked artifact',
      'a direct answer for must-not-appear properties: the marker is in the file or it is not',
    ],
    cannotReport: [
      'anything about code that is not a string -- a deleted branch, a removed wipe and a folded guard leave no string behind',
      'where in the pipeline a string was introduced or removed',
      'the difference between "absent because it was removed" and "absent because the scan could not see" -- which is why an oracle-control marker has to be found in the same scan for an absence to mean anything',
    ],
    verdictVocab: ['PRESENT', 'LOST', 'NO_MARKERS_DECLARED', 'VERIFICATION_INCOMPLETE'],
  },
  {
    id: 5,
    key: 'checksec',
    label: 'Hardening checker (checksec)',
    status: 'runnable',
    layer: 'artifact',
    reports: [
      'whole-artifact hardening posture: RELRO, stack canary, NX, PIE, RPATH/RUNPATH, FORTIFY',
    ],
    cannotReport: [
      'anything about a specific declared property -- its unit of analysis is the file, not a defence',
      'which pass changed anything: it never sees the pipeline, only the result',
      'per-function facts of any kind',
    ],
    verdictVocab: ['OUT_OF_SCOPE'],
    note:
      'This is the cleanest example of scope rather than deficiency. checksec '
      + 'answers "was this artifact built with the mitigations switched on", '
      + 'completely and cheaply. It was never asked "did admin_delete keep its '
      + 'authorization check", and no amount of improving it would make that '
      + 'question answerable from the same evidence.',
  },
  {
    id: 6,
    key: 'alive2',
    label: 'Alive2 (translation validation)',
    status: 'unsupported',
    unsupportedReason: 'TOOL_ABSENT',
    unsupportedDetail:
      'alive-tv is not installed on this host and building it needs z3 plus an '
      + 'LLVM build, which was not done in this session. This is a fact about '
      + 'our machine, not about Alive2.',
    layer: 'IR',
    relationship: 'complementary',
    reports: [
      '(when available) whether an optimisation was a refinement of its input -- i.e. whether the transformation was semantics-preserving in the language of the IR',
    ],
    cannotReport: [
      'whether a semantics-preserving transformation destroyed a security property. Deleting a dead store to a secret buffer is a correct optimisation; the whole problem is that it is correct',
      'attribution of a security property loss to a pass, because "security property" is not a term in its specification',
    ],
    verdictVocab: ['UNSUPPORTED'],
    note:
      'Explicitly NOT a competitor. The plan states the relationship as '
      + 'complementary: functional translation validation (is the transform '
      + 'sound?) versus security-property attribution (which pass removed this '
      + 'defence, and was the transform sound anyway?). A run of both would '
      + 'answer two questions, not rank two tools. No ranking is emitted for '
      + 'this arm, and none should be inferred from its absence.',
  },
  {
    id: 7,
    key: 'cc-prepost',
    label: 'compiler-side pre/post IR comparison only',
    status: 'runnable',
    layer: 'IR (endpoints)',
    reports: [
      'the effect count in the subject before the pipeline and after it',
      'a property state: PRESENT if the effect survived to post-optimisation IR, LOST if it did not',
    ],
    cannotReport: [
      'which pass did it -- there are only two samples, and everything between them is one opaque step',
      'a loss that happened and was then undone: two endpoints cannot see a round trip, and will report PRESENT for a property that spent most of the pipeline deleted',
      'a loss earlier than the pre-optimisation snapshot, e.g. anything the preprocessor removed',
    ],
    verdictVocab: ['PRESENT', 'LOST', 'ABSENT', 'NOT_OBSERVED', 'VERIFICATION_INCOMPLETE', 'NO_PROPERTY_DECLARED'],
    implementationScope:
      'Implemented here by textual callee matching in the printed .ll of the '
      + 'subject function. The plugin arm instead walks CallBase and compares '
      + 'the resolved callee (compiler/schema/interfaces.md §4). Textual '
      + 'matching is weaker -- a leftover `declare` is not a call, and a call '
      + 'through a cast is not a name -- and that difference belongs to this '
      + 'arm as implemented, not to the idea of endpoint comparison.',
  },
  {
    id: 8,
    key: 'cc-passlevel',
    label: 'compiler-side pass-level tracking (PropertyObserver)',
    status: 'runnable',
    layer: 'IR (every boundary)',
    reports: [
      'the state of the subject effect at every pass boundary',
      'first loss as a (pass, unit) pair with a sequence number',
      'final state, reintroduction, and loss-episode count as separate facts',
      'unit fate (erased/live) on its own channel, never merged into property loss',
      'SUBJECTRES: whether the configured names resolved in each module',
    ],
    cannotReport: [
      'a loss that happened before the first IR boundary. A defence removed by the preprocessor was never in the IR, so there is no pass to attribute it to -- the arm is silent by construction, and the honest record of that is LOSS_PRECEDES_WINDOW, not "no loss"',
      'whether the transformation that removed the effect was semantically sound (that is Alive2\'s question)',
      'anything about the linked artifact -- it stops at the end of the middle end',
      'a verdict about the run from one module: SUBJECTRES is a fact about one translation unit, and the run-level conclusion is drawn by tools/check-subject-resolution.mjs',
    ],
    verdictVocab: ['PRESENT', 'LOST', 'ABSENT', 'REINTRODUCED', 'NOT_OBSERVED', 'VERIFICATION_INCOMPLETE', 'NO_PROPERTY_DECLARED'],
  },
  {
    id: 9,
    key: 'beyond-integrated',
    label: 'Beyond integrated version',
    status: 'unsupported',
    unsupportedReason: 'SUBJECT_ABSENT',
    unsupportedDetail:
      'There is no implementation to run. No `beyond/` directory exists in the '
      + 'repository and nothing imports such a component. This is not a missing '
      + 'installation that could be fixed by installing something -- the '
      + 'comparison subject does not exist yet.',
    layer: 'n/a',
    reports: [],
    cannotReport: [
      'everything, at present. Any number attributed to this arm would be invented.',
    ],
    verdictVocab: ['UNSUPPORTED'],
    note:
      'Recorded as an arm so that its absence is visible in the same table as '
      + 'the arms that ran. Deleting the row would turn "we did not measure '
      + 'this" into "this was not part of the comparison", which is a different '
      + 'and false claim.',
  },
];

export const RUNNABLE_ARMS = ARMS.filter((a) => a.status === 'runnable');
export const UNSUPPORTED_ARMS = ARMS.filter((a) => a.status === 'unsupported');

export function armByKey(key) {
  const found = ARMS.find((a) => a.key === key);
  if (!found) throw new Error(`no such arm: ${key}`);
  return found;
}
