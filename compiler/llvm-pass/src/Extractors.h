// Targeted extractors: one per property class, each answering a question that
// was written down before the code was.
//
// There is no generic graph normaliser here on purpose. A normaliser has to
// decide what "the same thing" means for every property at once, and the
// decision it makes for a wipe is not the decision a fail-closed branch needs.
// Each extractor below carries its own notion of "the effect" and its own
// notion of "the thing the effect acts on", and says so in the record.
//
// Every one of them obeys compiler/schema/interfaces.md section 4:
//   * effects are counted by walking CallBase and resolving the callee, never
//     by asking the module whether a symbol exists;
//   * counting happens inside one IR unit;
//   * a control unit is counted alongside the subject at every checkpoint.

#ifndef IRCK_EXTRACTORS_H
#define IRCK_EXTRACTORS_H

#include "Record.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace irck {

enum class Extractor {
  /// Secure erasure. Effect = call sites to a wipe symbol, plus inline stores
  /// of zero into a stack buffer or a pointer parameter -- because above -O0
  /// the compiler is entitled to render a wipe either way, and an extractor
  /// that only knows the call form reports the control as lost.
  WipeEffect,
  /// Fail-closed branch / authorisation. Same call-site count, but it only
  /// counts while some conditional branch in the unit still tests a value. A
  /// branch on a constant decides nothing, so the call it guards is waiting to
  /// be swept up rather than protecting anything.
  GuardedCall,
  /// Forbidden call. Same walk, opposite polarity: a non-zero count is the
  /// finding.
  ForbiddenCallee,
};

const char *extractorName(Extractor E);
bool parseExtractor(const std::string &S, Extractor &Out);

enum class TargetKind { Alloca, Argument, Global, Other };
const char *targetKindName(TargetKind K);

/// What the effect acted on, at the point the effect was still there.
struct EffectTarget {
  TargetKind Kind = TargetKind::Other;
  /// Statically known size of the object in bytes; -1 when not an alloca or
  /// not statically known.
  int64_t SizeBytes = -1;
  /// true when the effect was a call site, false when it was an inline store.
  bool ViaCallSite = false;
  /// The object's IR name, when it has one. Size alone does not identify an
  /// object: two 16-byte allocas in one function are indistinguishable by size,
  /// and a checker that matched on size reported a promoted buffer as a deleted
  /// wipe whenever an unrelated object of the same size happened to survive.
  /// Empty when the name was discarded, which is a fact the verdict records
  /// rather than papers over.
  std::string Name;
};

/// One extractor's reading of one IR unit at one checkpoint.
struct UnitFacts {
  bool UnitPresent = false;

  int64_t EffectCallSites = 0;
  int64_t ZeroStores = 0;
  int64_t ForbiddenCallSites = 0;
  int64_t LiveCondBranches = 0;

  int64_t AllocaCount = 0;
  std::vector<int64_t> AllocaSizes; // statically known only, ascending
  /// (name, size) for every alloca in the unit, in program order and never
  /// sorted -- the pairing is the point, and sorting one half would break it.
  std::vector<std::pair<std::string, int64_t>> AllocaObjects;
  int64_t AllocasEscapingToOpaqueCall = 0;

  std::vector<EffectTarget> Targets;

  /// The number the oracle compares. Which counters feed it is the extractor's
  /// business and is recorded, so two channels cannot "agree" while asking
  /// different questions.
  int64_t effect(Extractor E) const;

  Json toJson(Extractor E) const;
};

struct ExtractorConfig {
  std::vector<std::string> EffectSymbols;
  std::vector<std::string> ForbiddenSymbols;
};

/// Read one IR unit. `F` may be a declaration; UnitPresent reports that.
UnitFacts collectFacts(const llvm::Function &F, const ExtractorConfig &C);

/// The naive oracle, kept and recorded precisely so the record can show what it
/// would have said. It asks the module whether a symbol exists -- the C++
/// spelling of a grep -- and a deleted call leaves the declaration behind, so
/// above -O0 it keeps answering "present" after the effect is gone.
bool naiveModuleSymbolPresent(const llvm::Module &M,
                              const std::vector<std::string> &Symbols);

/// Call sites to the effect symbols across the whole module. Recorded next to
/// the per-unit count so that interfaces.md section 4's second rule -- count
/// inside one IR unit -- is a number in the record rather than a promise: after
/// inlining these two diverge, and the module-wide one is the number that keeps
/// reporting an effect from a function nobody calls.
int64_t moduleWideCallSites(const llvm::Module &M,
                            const std::vector<std::string> &Symbols);

/// Effect symbols that the module still declares and nothing calls. This is the
/// residue a deleted call leaves behind, and it is the reason a name lookup is
/// not an oracle: it goes on answering "present" until an unrelated pass sweeps
/// the declaration away, which then gets the blame.
std::vector<std::string>
declaredButUncalledSymbols(const llvm::Module &M,
                           const std::vector<std::string> &Symbols);

} // namespace irck

#endif
