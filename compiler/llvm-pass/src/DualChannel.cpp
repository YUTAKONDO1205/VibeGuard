#include "DualChannel.h"

namespace irck {

const char *dualStateName(DualState S) {
  switch (S) {
  case DualState::ChannelsNotObserved: return "CHANNELS_NOT_OBSERVED";
  case DualState::AnnotationNotDeclared: return "ANNOTATION_NOT_DECLARED";
  case DualState::EffectNotEstablished: return "EFFECT_NOT_ESTABLISHED";
  case DualState::BothChannelsSurvived: return "BOTH_CHANNELS_SURVIVED";
  case DualState::AnnotationErasedEffectSurvived:
    return "ANNOTATION_ERASED_EFFECT_SURVIVED";
  case DualState::AnnotationSurvivedEffectErased:
    return "ANNOTATION_SURVIVED_EFFECT_ERASED";
  case DualState::BothChannelsErased: return "BOTH_CHANNELS_ERASED";
  case DualState::SubjectUnitAbsentAtPost: return "SUBJECT_UNIT_ABSENT_AT_POST";
  }
  return "CHANNELS_NOT_OBSERVED";
}

DualVerdict classifyDual(int64_t MetaPre, int64_t MetaPost, int64_t EffectPre,
                         int64_t EffectPost, bool UnitPresentPre,
                         bool UnitPresentPost, bool UnitScope) {
  DualVerdict V;

  if (UnitScope && !UnitPresentPre) {
    V.S = DualState::ChannelsNotObserved;
    V.Reason = "the unit was not present at the pre-optimisation checkpoint, so "
               "neither channel has a first reading to compare against";
    return V;
  }

  if (UnitScope && !UnitPresentPost) {
    V.S = DualState::SubjectUnitAbsentAtPost;
    V.Reason = "the unit is no longer a definition at the post-optimisation "
               "checkpoint; a per-unit reading of either channel would be a "
               "reading of something that is not there. The module-scope pair "
               "in this record is the one that still has a referent";
    return V;
  }

  // Order matters here, and the order is "say what was not measured before
  // saying what changed". A zero at the second checkpoint only means erasure if
  // there was something at the first.
  if (MetaPre == 0) {
    V.S = DualState::AnnotationNotDeclared;
    V.Reason =
        EffectPost > 0
            ? "no matching annotation was present at the pre-optimisation "
              "checkpoint, so the metadata channel measured nothing here; the "
              "structural channel still counts the effect. This is an "
              "undeclared effect, not an erased declaration"
            : "no matching annotation was present at the pre-optimisation "
              "checkpoint, so the metadata channel measured nothing here and "
              "its zero afterwards is not an erasure";
    return V;
  }

  if (EffectPre == 0) {
    V.S = DualState::EffectNotEstablished;
    V.Reason = "a matching annotation was present, but the structural channel "
               "counted no effect at the pre-optimisation checkpoint, so "
               "nothing structural was established for optimisation to remove";
    return V;
  }

  const bool MetaHeld = MetaPost > 0;
  const bool EffectHeld = EffectPost > 0;

  if (MetaHeld && EffectHeld) {
    V.S = DualState::BothChannelsSurvived;
    V.Reason = "the declaration and the processing both still read non-zero at "
               "the post-optimisation checkpoint";
    return V;
  }
  if (!MetaHeld && EffectHeld) {
    V.S = DualState::AnnotationErasedEffectSurvived;
    V.Reason = "the annotation that declared this property is gone while the "
               "structural channel still counts the effect: the metadata was "
               "removed, the processing was not. This is not LOST -- the "
               "program still does the declared thing, and only the evidence "
               "that it was declared has been optimised away";
    return V;
  }
  if (MetaHeld && !EffectHeld) {
    V.S = DualState::AnnotationSurvivedEffectErased;
    V.Reason = "the annotation survives while the structural channel counts no "
               "effect: the metadata now asserts something the code no longer "
               "does. A checker reading the metadata channel alone would call "
               "this clean";
    return V;
  }

  V.S = DualState::BothChannelsErased;
  V.Reason = "both channels reached zero at the post-optimisation checkpoint; "
             "which of them went first is in passHistory for the structural "
             "channel and is not observed pass-by-pass for the metadata one";
  return V;
}

} // namespace irck
