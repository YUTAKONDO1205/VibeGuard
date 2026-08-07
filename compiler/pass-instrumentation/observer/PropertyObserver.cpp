//===- PropertyObserver.cpp - the plugin entry point ----------------------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// An out-of-tree observer: the way of asking when a security property's effect
// disappeared that runs *inside* the compiler and walks the IR object model,
// rather than reading what the compiler prints.
//
// It registers callbacks only. It adds no pass, returns no analysis result and
// mutates nothing, so it cannot alter what the compiler produces -- and the
// byte-identity check in the harness is what confirms that claim rather than
// asserting it.
//
// Two mechanics are easy to get wrong and are worth naming:
//
//   * The IR unit arrives inside `llvm::Any` as a *pointer*. `any_cast<const
//     Function *>(&IR)` returns null when the unit is something else, which is
//     how the four unit kinds are told apart. The value form,
//     `any_cast<const Function *>(IR)`, throws / aborts on a type mismatch
//     instead, so probing with it is not an option.
//
//   * Nothing here keeps a `Function *` between callbacks. A pass may delete
//     the function it was handed, and a pointer kept across the boundary is a
//     use-after-free waiting for a pipeline that happens to reuse the memory.
//     The tracker stores names and looks them up again.
//
//===----------------------------------------------------------------------===//

#include "Config.h"
#include "History.h"

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
#include "llvm/Support/raw_ostream.h"

#include <memory>

using namespace llvm;
using namespace propobs;

namespace {

std::shared_ptr<Tracker> TheTracker;

/// One callback. `Count` is false for the skipped-pass callback: a pass that
/// did not run cannot have changed anything, and counting there would put an
/// observation into the history at a boundary that does not exist.
void dispatch(StringRef Phase, StringRef PassID, Any IR, bool Count) {
  std::shared_ptr<Tracker> T = TheTracker;
  if (!T || !T->ok())
    return;
  const uint64_t S = T->nextSeq();

  if (const auto **FP = any_cast<const Function *>(&IR)) {
    const Function *F = *FP;
    if (!F) {
      T->skipRecord(S, Phase, PassID);
      return;
    }
    T->passRecord(S, Phase, PassID, "function", F->getName());
    // Cheap census: a symbol-table lookup per tracked unit, which is what makes
    // a function deleted by some other pass visible here at all.
    T->syncModule(S, PassID, *F->getParent(), /*Full=*/false);
    if (Count)
      T->observe(S, Phase, PassID, "function", *F);
    return;
  }

  if (const auto **MP = any_cast<const Module *>(&IR)) {
    const Module *M = *MP;
    if (!M) {
      T->skipRecord(S, Phase, PassID);
      return;
    }
    T->passRecord(S, Phase, PassID, "module", M->getModuleIdentifier());
    // Full census at module boundaries: the only place a clone that did not
    // exist before can be discovered.
    T->syncModule(S, PassID, *M, /*Full=*/true);
    if (Count)
      for (const Function &F : *M)
        T->observe(S, Phase, PassID, "module", F);
    return;
  }

  if (const auto **CP = any_cast<const LazyCallGraph::SCC *>(&IR)) {
    const LazyCallGraph::SCC *C = *CP;
    if (!C) {
      T->skipRecord(S, Phase, PassID);
      return;
    }
    T->passRecord(S, Phase, PassID, "cgscc", C->getName());
    const Module *M = nullptr;
    for (const LazyCallGraph::Node &N : *C) {
      M = N.getFunction().getParent();
      break;
    }
    if (M)
      T->syncModule(S, PassID, *M, /*Full=*/false);
    if (Count)
      for (const LazyCallGraph::Node &N : *C)
        T->observe(S, Phase, PassID, "cgscc", N.getFunction());
    return;
  }

  if (const auto **LP = any_cast<const Loop *>(&IR)) {
    const Loop *L = *LP;
    const BasicBlock *H = L ? L->getHeader() : nullptr;
    const Function *F = H ? H->getParent() : nullptr;
    if (!F) {
      T->skipRecord(S, Phase, PassID);
      return;
    }
    T->passRecord(S, Phase, PassID, "loop", F->getName());
    T->syncModule(S, PassID, *F->getParent(), /*Full=*/false);
    if (Count)
      T->observe(S, Phase, PassID, "loop", *F);
    return;
  }

  // Some other unit kind (machine IR, a future one). Recorded rather than
  // dropped, so that a coverage figure computed from this log is honest about
  // what was not looked at.
  T->skipRecord(S, Phase, PassID);
}

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "property-observer", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            Config Cfg = loadConfig();
            if (!Cfg.Valid) {
              // Loud, because the alternative is an empty log that a driver
              // reads as "nothing was lost".
              errs() << "property-observer: refusing to install: "
                     << Cfg.Rejected << "\n";
              return;
            }
            const std::string OutPath = Cfg.OutPath;
            TheTracker = std::make_shared<Tracker>(std::move(Cfg));
            if (!TheTracker->ok()) {
              errs() << "property-observer: cannot open OBS_OUT (" << OutPath
                     << ")\n";
              TheTracker.reset();
              return;
            }

            PassInstrumentationCallbacks *PIC =
                PB.getPassInstrumentationCallbacks();
            if (!PIC) {
              errs() << "property-observer: no pass instrumentation callbacks; "
                        "nothing was observed\n";
              TheTracker.reset();
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
