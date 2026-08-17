// The metadata channel: the second of the two representations §10.4 asks for.
//
// The structural channel in Extractors.{h,cpp} re-derives the property from the
// code -- it counts call sites and stores. This one does the opposite: it reads
// what the *source* declared, as the declaration survives into IR, and never
// looks at what the code does.
//
// The point of having both is a single sentence: **metadata disappearing is not
// the same event as processing disappearing.** Either can go without the other,
// and a checker with one channel cannot tell which happened. So the two are
// counted separately, recorded side by side, and combined only into a name that
// keeps the pair legible -- see DualState in DualChannel.h.
//
// The carrier is measured, not assumed. `__attribute__((annotate("...")))`
// reaches IR with no Clang plugin loaded (measured with clang-18 18.1.3 at -O0
// through -O3), in exactly two forms:
//
//   * on a function -> one entry in the appending global
//     `@llvm.global.annotations`, whose first field is the function and whose
//     second is a pointer to the annotation string;
//   * on a local variable -> a call to `@llvm.var.annotation.p0.p0` inside the
//     function, whose second argument is a pointer to the annotation string.
//
// Both are read here. Nothing else is: `!annotation` instruction metadata was
// looked for in optimised output and was not found (Annotation2MetadataPass
// left the probe module unchanged), so no reader for it is written -- an
// unexercised reader would be a claim the measurement does not support.

#ifndef IRCK_METADATA_CHANNEL_H
#define IRCK_METADATA_CHANNEL_H

#include "Record.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace irck {

struct MetadataConfig {
  /// Annotations are counted only when the string starts with this. An empty
  /// prefix counts every annotation in the module, which is a different
  /// measurement and is recorded as such.
  std::string Prefix = "vg:property:";
};

/// One unit's reading on the metadata channel at one checkpoint.
struct UnitMetadata {
  bool UnitPresent = false;

  /// Entries in @llvm.global.annotations whose annotated value is this
  /// function and whose string matches the prefix.
  int64_t FunctionAnnotations = 0;
  /// llvm.var.annotation / llvm.ptr.annotation call sites inside this function
  /// whose string matches the prefix.
  int64_t LocalAnnotations = 0;
  /// Annotations on this unit that exist but do not match the prefix. Recorded
  /// so that "this unit declares nothing" and "the prefix is pointed at the
  /// wrong vocabulary" are different readings rather than the same zero -- the
  /// same failure `pc4-wrong-symbol` exists to catch on the other channel.
  int64_t NonMatchingAnnotations = 0;

  /// The matched strings, sorted and deduplicated.
  std::vector<std::string> Strings;

  /// The number the dual-channel classification compares.
  int64_t present() const { return FunctionAnnotations + LocalAnnotations; }

  Json toJson() const;
};

/// The whole module's reading, for the case the subject unit stops existing.
/// A unit-scope metadata count cannot be taken from a unit that is gone, and
/// substituting zero for it would be exactly the "did not look" reported as
/// "not there" that this component exists to refuse.
struct ModuleMetadata {
  /// Does the module carry the carrier at all, matching or not? Distinguishes
  /// "compiled without annotations" from "annotated with another vocabulary".
  bool CarrierPresent = false;
  int64_t FunctionAnnotations = 0;
  int64_t LocalAnnotations = 0;
  int64_t NonMatchingAnnotations = 0;
  /// Names of the functions carrying a matching function-level annotation,
  /// sorted. This is what goes missing when a function is deleted.
  std::vector<std::string> AnnotatedFunctions;
  std::vector<std::string> Strings;

  int64_t present() const { return FunctionAnnotations + LocalAnnotations; }

  Json toJson() const;
};

/// `F` may be a declaration; UnitPresent reports that, and the counts are then
/// whatever the module still says about the name (a function-level annotation
/// outlives the body).
UnitMetadata collectUnitMetadata(const llvm::Function &F, const MetadataConfig &C);

ModuleMetadata collectModuleMetadata(const llvm::Module &M, const MetadataConfig &C);

} // namespace irck

#endif
