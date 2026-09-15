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
//   * There is no process-global tracker. The registration callback below runs
//     once per `PassBuilder`, and under `-flto=thin` lld builds one per backend
//     module, each on its own thread. A file-scope `shared_ptr<Tracker>` --
//     which is what stood here until this change -- meant every backend
//     assigned over it, destroying the previous tracker mid-run, and every one
//     of them opened and wrote the same log concurrently. The surviving file
//     was whatever the interleaving left: several modules' records spliced
//     together, lines torn mid-field, and nothing in it saying so. Each
//     `PassBuilder` now owns its tracker, the three callbacks it installs
//     capture a `shared_ptr` to it, and `dispatch` takes it from that capture
//     rather than reading a variable another thread is writing.
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

/// One callback. `Count` is false for the skipped-pass callback: a pass that
/// did not run cannot have changed anything, and counting there would put an
/// observation into the history at a boundary that does not exist.
///
/// The tracker arrives as an argument because it belongs to the `PassBuilder`
/// these callbacks were installed on -- see the note at the top about why it
/// cannot be a global.
void dispatch(const std::shared_ptr<Tracker> &T, StringRef Phase,
              StringRef PassID, Any IR, bool Count) {
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
              // reads as "nothing was lost". One `<<` of one string, here and
              // below: several backend threads share this stderr under ThinLTO
              // and a message split across writes comes back spliced mid-word.
              const std::string Msg =
                  "property-observer: refusing to install: " + Cfg.Rejected +
                  "\n";
              errs() << Msg;
              return;
            }

            PassInstrumentationCallbacks *PIC =
                PB.getPassInstrumentationCallbacks();
            if (!PIC) {
              const std::string Msg =
                  "property-observer: no pass instrumentation callbacks; "
                  "nothing was observed\n";
              errs() << Msg;
              return;
            }

            // Whether the log can be opened is no longer knowable here. The
            // name it will be opened under depends on which module this
            // `PassBuilder` turns out to be for, and that is not decided until
            // the first module boundary, so the open -- and the diagnostic for
            // a path that will not open -- moved into `Tracker::openFor`.
            //
            // The three lambdas hold the only references to the tracker, so it
            // dies with the `PassInstrumentationCallbacks`, and that is what
            // runs `Tracker::finish()`.
            //
            // THIS CHANGED WHAT A LINK LEAVES BEHIND, and the change is worth
            // stating because a whole paragraph of the lto-window README rested
            // on the old behaviour. The tracker used to be a file-scope global,
            // which lld never destroys -- it exits without unwinding -- so
            // `finish()` did not run at link time and the main log of a healthy
            // full-LTO link carried no `SUMMARY`, `HIST` or `STATS` at all; the
            // attribution survived only because `writeSummaryFile()` rewrites
            // the side file on every change. lld DOES destroy the callbacks, so
            // a tracker owned by them is finished at link as well as at compile.
            // Measured 2026-09-14 on a full-LTO link of the lto-window `xtu`
            // fixture: the main log now holds 2 `SUMMARY`, 4 `HIST` and 1
            // `STATS` beside its 448 `PASS` and 388 `EV` records, and the
            // lane's `counts.summarySource` reads `main` where it read `side`.
            // That closes a hazard rather than opening one -- the file the lane
            // guards and the file its verdict comes out of are now the same
            // file under full LTO -- but any reader that treated "no SUMMARY in
            // the main log" as the signature of a link is now wrong.
            auto T = std::make_shared<Tracker>(std::move(Cfg));

            PIC->registerBeforeNonSkippedPassCallback(
                [T](StringRef PassID, Any IR) {
                  dispatch(T, "before", PassID, IR, /*Count=*/true);
                });
            PIC->registerAfterPassCallback(
                [T](StringRef PassID, Any IR, const PreservedAnalyses &) {
                  dispatch(T, "after", PassID, IR, /*Count=*/true);
                });
            PIC->registerBeforeSkippedPassCallback(
                [T](StringRef PassID, Any IR) {
                  dispatch(T, "skipped", PassID, IR, /*Count=*/false);
                });
          }};
}
