//===- Oracle.cpp ---------------------------------------------------------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//

#include "Oracle.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace propobs {

bool hasLiveConditionalBranch(const Function &F) {
  for (const BasicBlock &BB : F) {
    const auto *BI = dyn_cast_or_null<BranchInst>(BB.getTerminator());
    if (BI && BI->isConditional() && !isa<Constant>(BI->getCondition()))
      return true;
  }
  return false;
}

unsigned countEffect(const Function &F, const std::vector<std::string> &Symbols,
                     bool RequireLiveBranch) {
  if (RequireLiveBranch && !hasLiveConditionalBranch(F))
    return 0;
  unsigned N = 0;
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      const auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;
      const Function *Callee = CB->getCalledFunction();
      if (!Callee)
        continue;
      StringRef Name = Callee->getName();
      for (const std::string &S : Symbols) {
        if (Name == S) {
          N++;
          break;
        }
        // Intrinsics carry a type suffix: llvm.memset -> llvm.memset.p0.i64
        if (Name.starts_with(S) && Name.size() > S.size() &&
            Name[S.size()] == '.') {
          N++;
          break;
        }
      }
    }
  }
  return N;
}

/// Strip one trailing clone suffix, if the name has one. Returns false when
/// nothing was stripped.
static bool stripOneSuffix(StringRef &Name) {
  // The numeric tail first: every one of these suffixes may or may not carry
  // one, and `.llvm.10412843` is `.llvm` plus a number rather than a suffix of
  // its own.
  size_t Dot = Name.rfind('.');
  if (Dot == StringRef::npos || Dot == 0 || Dot + 1 >= Name.size())
    return false;
  StringRef Tail = Name.substr(Dot + 1);

  bool AllDigits = true;
  for (char C : Tail)
    if (C < '0' || C > '9')
      AllDigits = false;
  if (AllDigits) {
    Name = Name.substr(0, Dot);
    return true;
  }

  // Named suffixes. `.cold` and `.part` are outlined fragments rather than
  // whole clones, but they belong to the same lineage for the purpose of
  // grouping, and grouping is all this is used for.
  static const char *const Named[] = {"llvm",  "specialized", "__uniq",
                                      "cold",  "constprop",   "part",
                                      "isra",  "internal",    "clone"};
  for (const char *S : Named) {
    if (Tail == S) {
      Name = Name.substr(0, Dot);
      return true;
    }
  }
  return false;
}

std::string lineageRoot(StringRef Name) {
  StringRef Cur = Name;
  // Bounded so that a pathological name cannot spin here.
  for (unsigned I = 0; I < 8; ++I) {
    StringRef Before = Cur;
    if (!stripOneSuffix(Cur))
      break;
    if (Cur.empty()) {
      Cur = Before;
      break;
    }
  }
  return Cur.str();
}

} // namespace propobs
