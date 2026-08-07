//===- IntroductionObserver.cpp - the plugin entry point ------------------===//
//
// Part of the introduction observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// The mirror of the property observer: instead of asking when a security
// property's effect disappeared, it asks when something appeared that was not
// there before, and which pass, on which IR unit, put it there.
//
// It registers callbacks only. It adds no pass, returns no analysis result and
// mutates nothing, so it cannot change what the compiler produces -- and the
// byte-identity check in tools/live.sh is what confirms that rather than
// asserting it.
//
// Two mechanics worth naming, both learned from the observer next door:
//
//   * The IR unit arrives inside `llvm::Any` as a *pointer*.
//     `any_cast<const Function *>(&IR)` returns null when the unit is something
//     else, which is how the four unit kinds are told apart. The value form
//     aborts on a type mismatch, so probing with it is not an option.
//
//   * Nothing keeps a `Function *` between callbacks. A pass may delete the
//     function it was handed; a pointer kept across the boundary is a
//     use-after-free waiting for a pipeline that reuses the memory. Everything
//     is kept by name.
//
// WHY THE MODULE SCOPE IS CENSUSED AT EVERY CALLBACK, INCLUDING FUNCTION ONES.
// A pass that runs on function F can add a global, a static initialiser or a
// whole new function to the module; nothing announces it, and if the census
// only ran at module boundaries the introduction would be attributed to the
// next module pass instead of to the pass that did it. The module-scope census
// walks symbol tables and never bodies, so paying it per callback is a
// symbol-table iteration, not a walk of the program.
//
//===----------------------------------------------------------------------===//

#include "Census.h"
#include "Config.h"

#include "llvm/ADT/Any.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LazyCallGraph.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>

using namespace llvm;
using namespace introobs;

namespace {

std::shared_ptr<Census> TheCensus;

/// The module identifier is the path the driver was given, and on a checkout
/// reached over a mount that is an absolute path with an account name in it.
/// interfaces.md §5 forbids an absolute path anywhere in a record, so the unit
/// name for a module is its file name and nothing more. Measured: without this
/// the log named the whole `/mnt/...` path on every module-scope record.
StringRef shortModuleId(const Module &M) {
  return sys::path::filename(M.getModuleIdentifier());
}

/// `Count` is false for the skipped-pass callback: a pass that did not run
/// cannot have introduced anything, and taking a census there would put an
/// observation into the series at a boundary that does not exist.
void dispatch(StringRef Phase, StringRef PassID, Any IR, bool Count) {
  std::shared_ptr<Census> C = TheCensus;
  if (!C || !C->ok()) return;
  const uint64_t S = C->nextSeq();

  if (const auto **FP = any_cast<const Function *>(&IR)) {
    const Function *F = *FP;
    if (!F) { C->skipRecord(S, Phase, PassID); return; }
    C->passRecord(S, Phase, PassID, "function", F->getName());
    if (!Count) return;
    C->syncModuleScope(S, Phase, PassID, "function", F->getName(), *F->getParent());
    C->syncFunctionScope(S, Phase, PassID, "function", F->getName(), *F);
    return;
  }

  if (const auto **MP = any_cast<const Module *>(&IR)) {
    const Module *M = *MP;
    if (!M) { C->skipRecord(S, Phase, PassID); return; }
    const StringRef ModId = shortModuleId(*M);
    C->passRecord(S, Phase, PassID, "module", ModId);
    if (!Count) return;
    C->syncModuleScope(S, Phase, PassID, "module", ModId, *M);
    // The only boundary at which every function scope is enumerated, and so the
    // only place a call site introduced into a function that no later
    // function-pass callback visits can be discovered at all.
    for (const Function &F : *M)
      if (!F.isDeclaration())
        C->syncFunctionScope(S, Phase, PassID, "module", ModId, F);
    return;
  }

  if (const auto **CP = any_cast<const LazyCallGraph::SCC *>(&IR)) {
    const LazyCallGraph::SCC *Comp = *CP;
    if (!Comp) { C->skipRecord(S, Phase, PassID); return; }
    C->passRecord(S, Phase, PassID, "cgscc", Comp->getName());
    if (!Count) return;
    const Module *M = nullptr;
    for (const LazyCallGraph::Node &N : *Comp) { M = N.getFunction().getParent(); break; }
    if (M) C->syncModuleScope(S, Phase, PassID, "cgscc", Comp->getName(), *M);
    for (const LazyCallGraph::Node &N : *Comp)
      C->syncFunctionScope(S, Phase, PassID, "cgscc", Comp->getName(), N.getFunction());
    return;
  }

  if (const auto **LP = any_cast<const Loop *>(&IR)) {
    const Loop *L = *LP;
    const BasicBlock *H = L ? L->getHeader() : nullptr;
    const Function *F = H ? H->getParent() : nullptr;
    if (!F) { C->skipRecord(S, Phase, PassID); return; }
    C->passRecord(S, Phase, PassID, "loop", F->getName());
    if (!Count) return;
    C->syncModuleScope(S, Phase, PassID, "loop", F->getName(), *F->getParent());
    C->syncFunctionScope(S, Phase, PassID, "loop", F->getName(), *F);
    return;
  }

  // Some other unit kind (machine IR, or a future one). Recorded rather than
  // dropped, so that a coverage figure computed from this log is honest about
  // what was not looked at.
  C->skipRecord(S, Phase, PassID);
}

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "introduction-observer", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            Config Cfg = loadConfig();
            if (!Cfg.Valid) {
              // Loud, because the alternative is an empty log that a reader
              // takes for "nothing was introduced".
              errs() << "introduction-observer: refusing to install: "
                     << Cfg.Rejected << "\n";
              return;
            }
            const std::string OutPath = Cfg.OutPath;
            TheCensus = std::make_shared<Census>(std::move(Cfg));
            if (!TheCensus->ok()) {
              errs() << "introduction-observer: cannot open INTRO_OUT ("
                     << OutPath << ")\n";
              TheCensus.reset();
              return;
            }

            PassInstrumentationCallbacks *PIC =
                PB.getPassInstrumentationCallbacks();
            if (!PIC) {
              errs() << "introduction-observer: no pass instrumentation "
                        "callbacks; nothing was observed\n";
              TheCensus.reset();
              return;
            }

            PIC->registerBeforeNonSkippedPassCallback(
                [](StringRef PassID, Any IR) {
                  dispatch("before", PassID, IR, /*Count=*/true);
                });
            PIC->registerAfterPassCallback(
                [](StringRef PassID, Any IR, const PreservedAnalyses &) {
                  dispatch("after", PassID, IR, /*Count=*/true);
                });
            PIC->registerBeforeSkippedPassCallback(
                [](StringRef PassID, Any IR) {
                  dispatch("skipped", PassID, IR, /*Count=*/false);
                });
          }};
}
