// The combination of the two channels -- and the reason it is a vocabulary of
// its own rather than a reuse of the six states in interfaces.md section 3.
//
// Those six (PRESENT / ABSENT / LOST / REINTRODUCED / NOT_APPLICABLE /
// NOT_OBSERVED) are the *structural* channel's answers: they describe what the
// code does. Saying "LOST" because an annotation went missing would put a word
// that means "the program stopped doing the thing" on an event where the
// program still does the thing. That is the substitution the design plan section 10.4 names
// -- "metadata が消えた ≠ 処理が消えた" -- so the two vocabularies are kept
// disjoint, checked by grep before these names were chosen.
//
// Four of the states below are the four cells of (metadata present or not) x
// (structure present or not) at the post-optimisation checkpoint. They are
// never collapsed into each other:
//
//   metadata | structure | state
//   ---------+-----------+-------------------------------------
//   present  | present   | BOTH_CHANNELS_SURVIVED
//   absent   | present   | ANNOTATION_ERASED_EFFECT_SURVIVED   <- §10.4's case
//   present  | absent    | ANNOTATION_SURVIVED_EFFECT_ERASED   <- the metadata lies
//   absent   | absent    | BOTH_CHANNELS_ERASED
//
// The other four exist so the table above is only entered when it means
// something. Reading "the annotation is absent at the end" as an erasure when
// there was never an annotation to erase would be the same class of error in
// the other direction, and a fixture compiled without annotations would then
// report the headline finding by default.
//
// Nothing here decides pass or fail and nothing here touches `verdict.state`.
// The structural verdict is left exactly as it was; this is recorded beside it.

#ifndef IRCK_DUAL_CHANNEL_H
#define IRCK_DUAL_CHANNEL_H

#include <cstdint>
#include <string>

namespace irck {

enum class DualState {
  /// The unit was not there to read at the first checkpoint. No pair exists.
  ChannelsNotObserved,
  /// The unit was there but carried no matching annotation at the first
  /// checkpoint. The metadata channel measured nothing here, so its zero at the
  /// second checkpoint is not an erasure.
  AnnotationNotDeclared,
  /// The annotation was there and the structural effect was already zero at the
  /// first checkpoint. Nothing structural was established to survive.
  EffectNotEstablished,
  /// Both channels still read non-zero at the second checkpoint.
  BothChannelsSurvived,
  /// The declaration is gone and the processing is still there. NOT a loss of
  /// the property: the program still does what was declared, and only the
  /// evidence that it was declared has gone. Never reported as LOST.
  AnnotationErasedEffectSurvived,
  /// The declaration is still there and the processing is gone -- the metadata
  /// now asserts something the code no longer does. A checker that trusted the
  /// metadata channel alone would report this as fine.
  AnnotationSurvivedEffectErased,
  /// Both channels reached zero.
  BothChannelsErased,
  /// Unit scope only: the unit itself is gone at the second checkpoint, so
  /// neither channel's second reading is about the same referent. The
  /// module-scope pair in the same record is the one that still says something.
  SubjectUnitAbsentAtPost,
};

const char *dualStateName(DualState S);

struct DualVerdict {
  DualState S = DualState::ChannelsNotObserved;
  std::string Reason;
};

/// `UnitScope` selects whether unit presence is part of the question. At module
/// scope there is no unit to be absent, so the two unit-presence flags are
/// ignored and must be passed as true.
DualVerdict classifyDual(int64_t MetaPre, int64_t MetaPost, int64_t EffectPre,
                         int64_t EffectPost, bool UnitPresentPre,
                         bool UnitPresentPost, bool UnitScope);

} // namespace irck

#endif
