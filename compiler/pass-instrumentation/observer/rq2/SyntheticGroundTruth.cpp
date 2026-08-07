//===- SyntheticGroundTruth.cpp -------------------------------------------===//
//
// Ground truth for the "which pass lost the property" question.
//
// Measuring the accuracy of a first-loss attribution needs a compilation whose
// answer is already known, and no real pipeline has one -- which pass removed
// an effect is exactly what is in dispute. So this plugin supplies passes that
// remove, restore, delete and clone by construction, and the harness places
// them at positions it chose. The answer is then known because the harness
// wrote it, not because a tool agreed with another tool.
//
// This is a measurement instrument. It mutates IR on purpose and is the exact
// opposite of the observer it is used to test; it lives outside the repository,
// with the rest of the measurement workspace, and is never loaded by a real
// build.
//
// Build:
//   cmake -S ~/vg-lab/pass-observer/rq2 -B ~/vg-build/pass-observer-rq2 \
//         -G Ninja -DLLVM_DIR=$(llvm-config-18 --cmakedir)
//   ninja -C ~/vg-build/pass-observer-rq2
//
// Configuration (environment):
//   SGT_FN        function to operate on
//   SGT_SYMBOLS   comma-separated effect symbols, same spelling as OBS_EFFECT_SYMBOLS
//   SGT_CLONE_SUFFIX  suffix for synthetic-clone (default ".llvm.4242")
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <cstdlib>
#include <string>
#include <vector>

using namespace llvm;

namespace {

std::string envOr(const char *N, const char *D) {
  const char *V = std::getenv(N);
  return V ? std::string(V) : std::string(D);
}

std::vector<std::string> splitCommas(const std::string &S) {
  std::vector<std::string> Out;
  std::string Cur;
  for (char C : S) {
    if (C == ',') {
      if (!Cur.empty())
        Out.push_back(Cur);
      Cur.clear();
    } else {
      Cur.push_back(C);
    }
  }
  if (!Cur.empty())
    Out.push_back(Cur);
  return Out;
}

std::string targetFn() { return envOr("SGT_FN", ""); }

bool isEffect(StringRef Name) {
  static const std::vector<std::string> Syms =
      splitCommas(envOr("SGT_SYMBOLS", ""));
  for (const std::string &S : Syms) {
    if (Name == S)
      return true;
    if (Name.starts_with(S) && Name.size() > S.size() && Name[S.size()] == '.')
      return true;
  }
  return false;
}

} // namespace

/// Delete the first call to an effect symbol. This is the injected cause: the
/// harness knows which pass ran it and where, so the correct attribution is
/// known before the observer is asked.
struct SyntheticErasePass : PassInfoMixin<SyntheticErasePass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.getName() != targetFn())
      return PreservedAnalyses::all();
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
          continue;
        Function *Callee = CB->getCalledFunction();
        if (!Callee || !isEffect(Callee->getName()))
          continue;
        if (!CB->use_empty())
          CB->replaceAllUsesWith(PoisonValue::get(CB->getType()));
        CB->eraseFromParent();
        return PreservedAnalyses::none();
      }
    }
    return PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

/// Put a counted effect back, in a form nothing downstream may remove (the
/// memset is volatile). This is how a PRESENT -> LOST -> REINTRODUCED sequence
/// is produced on demand.
struct SyntheticRestorePass : PassInfoMixin<SyntheticRestorePass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.getName() != targetFn() || F.isDeclaration())
      return PreservedAnalyses::all();
    BasicBlock &Entry = F.getEntryBlock();
    IRBuilder<> B(&*Entry.getFirstInsertionPt());
    AllocaInst *A =
        B.CreateAlloca(B.getInt8Ty(), B.getInt64(32), "synthetic.scratch");
    B.CreateMemSet(A, B.getInt8(0), B.getInt64(32), MaybeAlign(1),
                   /*isVolatile=*/true);
    return PreservedAnalyses::none();
  }
  static bool isRequired() { return true; }
};

/// Delete the whole function. The point of having this is that a deleted
/// function stops producing callbacks silently, so an observer that does not
/// keep its own census reports its last sighting for ever.
struct SyntheticDeleteUnitPass : PassInfoMixin<SyntheticDeleteUnitPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    Function *F = M.getFunction(targetFn());
    if (!F || F->isDeclaration())
      return PreservedAnalyses::all();
    if (!F->use_empty())
      F->replaceAllUsesWith(UndefValue::get(F->getType()));
    F->eraseFromParent();
    return PreservedAnalyses::none();
  }
  static bool isRequired() { return true; }
};

/// Clone the function under a name of the shape the inliner and function
/// specialisation produce. Used to check that a clone starting its own history
/// is recorded as a birth rather than as the return of something lost.
struct SyntheticClonePass : PassInfoMixin<SyntheticClonePass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    Function *F = M.getFunction(targetFn());
    if (!F || F->isDeclaration())
      return PreservedAnalyses::all();
    ValueToValueMapTy VMap;
    Function *C = CloneFunction(F, VMap);
    C->setName(F->getName() + envOr("SGT_CLONE_SUFFIX", ".llvm.4242"));
    return PreservedAnalyses::none();
  }
  static bool isRequired() { return true; }
};

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "synthetic-ground-truth",
          LLVM_VERSION_STRING, [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "synthetic-erase") {
                    FPM.addPass(SyntheticErasePass());
                    return true;
                  }
                  if (Name == "synthetic-restore") {
                    FPM.addPass(SyntheticRestorePass());
                    return true;
                  }
                  return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "synthetic-delete-unit") {
                    MPM.addPass(SyntheticDeleteUnitPass());
                    return true;
                  }
                  if (Name == "synthetic-clone") {
                    MPM.addPass(SyntheticClonePass());
                    return true;
                  }
                  return false;
                });
          }};
}
