//===- Oracle.h - counting an effect inside one IR unit -------------------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// The counting rule is fixed by compiler/schema/interfaces.md section 4 and is
// not this component's to reinterpret: count call sites inside one IR unit,
// never symbol names, because a deleted call leaves its `declare` behind and a
// name search then blames whichever pass eventually sweeps the declaration away
// instead of the pass that removed the call.
//
//===----------------------------------------------------------------------===//

#ifndef PROPERTY_OBSERVER_ORACLE_H
#define PROPERTY_OBSERVER_ORACLE_H

#include "llvm/ADT/StringRef.h"

#include <string>
#include <vector>

namespace llvm {
class Function;
} // namespace llvm

namespace propobs {

/// Is there still a conditional branch whose condition is a value?
///
/// A branch on a constant decides nothing; the block it guards is already
/// unreachable, and the call inside it is waiting to be swept up rather than
/// protecting anything.
bool hasLiveConditionalBranch(const llvm::Function &F);

/// Call sites to any of the effect symbols, inside one function.
///
/// This walks call instructions, so a declaration left behind by a deleted call
/// is not visible here at all -- the same rule a text-based oracle has to
/// implement with care is structural in this representation.
unsigned countEffect(const llvm::Function &F,
                     const std::vector<std::string> &Symbols,
                     bool RequireLiveBranch);

/// The lineage a function name belongs to.
///
/// A name is not an identity. The inliner, function specialisation and
/// internal-name uniquing all produce clones whose names are the original with
/// a suffix -- `handle_request.llvm.10412843`, `handle_request.specialized.1`,
/// `handle_request.__uniq.99`. Keying a state history by name splits one
/// logical function into two histories: the original goes LOST when it is
/// deleted, the clone starts a fresh history whose first observation is
/// PRESENT, and a reader who merges them by name sees a reintroduction that
/// never happened.
///
/// So the observer keys per concrete unit (each clone keeps its own history,
/// which is what makes the false reintroduction impossible) and groups those
/// units by the lineage this function computes.
///
/// Returns the input unchanged when no clone suffix is present.
std::string lineageRoot(llvm::StringRef Name);

} // namespace propobs

#endif // PROPERTY_OBSERVER_ORACLE_H
