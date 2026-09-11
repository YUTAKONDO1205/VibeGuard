// WipePin -- the deliberately invasive repair plugin.
//
// This pass changes the object file on purpose. Everything else under
// compiler/ that loads into clang is an observer and is measured to leave the
// output byte-identical; this one exists to make the output different, in one
// narrow way: a zero-fill llvm.memset in a selected function is marked
// volatile, so no later pass may delete it as a dead store.
//
// It is the "repair" in find -> repair -> confirm. It is never the "confirm":
// the record written here says what this pass did to the IR, and whether the
// wipe then survived to the assembly is decided by the same stock observation
// that found it missing, re-run with this plugin loaded. A repair tool that
// grades its own repair has only measured its own intentions.
//
// Two properties are load-bearing, as in MarkerPass next door:
//
//   1. It registers on the pipeline-start extension point, so -fpass-plugin=
//      alone makes it run, and it runs before SROA, InstCombine and DSE ever
//      see the memset. A pass that ran after them would find nothing left to
//      pin in exactly the cases it exists for.
//   2. isRequired() is true, so an optnone function (every function at -O0) is
//      not skipped. A pin that silently did not happen at -O0 would be a record
//      saying one thing and an object saying another.
//
// Configuration and its refusals are in PinSelector.h.

#include "PinSelector.h"
#include "Record.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;

namespace wpin {

using irck::Json;

namespace {

/// The pointer parameter a load reads back, if the load is from the stack slot
/// the front end spilled that parameter to and the slot is used for nothing
/// else.
///
/// This pass runs at pipeline start, before SROA, so a wipe through a pointer
/// parameter does not address the Argument: it addresses whatever was loaded
/// from `%p.addr`. Without this, every such wipe would be classified "other"
/// and "argument" would be a word the record could never contain. It sees
/// through exactly that one front-end shape and nothing more general.
const Argument *spilledArgument(const LoadInst &LI) {
  const auto *Slot =
      dyn_cast<AllocaInst>(LI.getPointerOperand()->stripPointerCasts());
  if (!Slot) return nullptr;
  const Argument *Found = nullptr;
  for (const User *U : Slot->users()) {
    if (const auto *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getPointerOperand() != Slot) return nullptr; // the slot escapes
      const auto *A = dyn_cast<Argument>(SI->getValueOperand());
      if (!A || (Found && Found != A)) return nullptr;
      Found = A;
      continue;
    }
    if (isa<LoadInst>(U)) continue;
    if (const auto *II = dyn_cast<IntrinsicInst>(U))
      if (II->isLifetimeStartOrEnd()) continue;
    return nullptr;
  }
  return Found;
}

/// The same four words, with the same meaning, as classifyTarget in
/// compiler/llvm-pass/src/Extractors.cpp, so a pinned site and an observed
/// effect target can be read side by side -- with the one difference that this
/// reads pre-SROA IR, hence spilledArgument above.
const char *destKindOf(const Value *Dest) {
  const Value *UO = getUnderlyingObject(Dest);
  if (isa<AllocaInst>(UO)) return "alloca";
  if (isa<Argument>(UO)) return "argument";
  if (isa<GlobalValue>(UO)) return "global";
  if (const auto *LI = dyn_cast<LoadInst>(UO))
    if (spilledArgument(*LI)) return "argument";
  return "other";
}

bool isZeroFill(const MemSetInst &MS) {
  const auto *CI = dyn_cast<ConstantInt>(MS.getValue());
  return CI && CI->isZero();
}

struct Site {
  std::string Function;
  int64_t Index = 0;
  bool HaveLength = false;
  int64_t LengthBytes = 0;
  std::string DestKind;
  bool AlreadyVolatile = false;
  bool HaveLine = false;
  int64_t Line = 0;
};

struct Unhandled {
  int64_t LibcallMemset = 0;
  int64_t MemsetChk = 0;
  int64_t NonZeroFill = 0;
  int64_t AtomicMemset = 0;
  /// A call to `memset.inline` (or any `memset.<suffix>` that is not the
  /// intrinsic). Measured: under -D_FORTIFY_SOURCE=2 with glibc's headers,
  /// clang renames the header's gnu_inline memset wrapper to `memset.inline`,
  /// and at pipeline start the target function calls THAT -- the llvm.memset
  /// or __memset_chk is inside the wrapper, out of scope. Without this counter
  /// the fortified wipe was pinned by nobody and counted by nobody.
  int64_t InlineWrapperMemset = 0;
};

/// Modules this process has handed to the pass. One compiler process should
/// hand it exactly one; if a host ever hands it two, the second record
/// overwrites the first, and that is said out loud rather than prevented.
///
/// This does NOT catch two source files on one clang driver line. Measured on
/// clang 18.1.3 with `-c a.c b.c`: this warning did not appear, rc was 0, and
/// the one record left named b.c only -- each file reached a fresh copy of this
/// counter, so whichever finished last owns WPIN_OUT. scripts/pin.sh counts
/// source operands and warns about that case instead.
unsigned ModulesSeen = 0;

int64_t countZeroFillIn(const Function &F) {
  int64_t N = 0;
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB)
      if (const auto *MS = dyn_cast<MemSetInst>(&I))
        if (isZeroFill(*MS)) N++;
  return N;
}

} // namespace

class WipePinPass : public PassInfoMixin<WipePinPass> {
public:
  WipePinPass(std::shared_ptr<const Config> C, OptimizationLevel L)
      : Cfg(std::move(C)), Level(L) {}

  // Named explicitly so -fdebug-pass-manager prints "WipePinPass" rather than
  // a namespace-qualified template spelling that differs between compilers.
  static StringRef name() { return "WipePinPass"; }

  // Run even when the function is optnone. See the header comment.
  static bool isRequired() { return true; }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const Config &C = *Cfg;
    const std::string ModuleName =
        sys::path::filename(M.getModuleIdentifier()).str();

    if (++ModulesSeen > 1)
      errs() << "WipePin: a second module (" << ModuleName
             << ") reached this pass in one process; the record at WPIN_OUT is "
                "overwritten and describes this module only\n";

    // --- which functions are in scope, and did the names exist -------------
    std::vector<Function *> InScope;
    Json ResolutionJ = Json::array();
    Json RequestedJ = Json::array();
    if (C.S == Scope::Functions) {
      for (const std::string &N : C.Requested) {
        RequestedJ.push(Json::str(N));
        const Resolution R = resolve(M, N);
        ResolutionJ.push(Json::object()
                             .set("name", Json::str(N))
                             .set("resolution", Json::str(resolutionName(R))));
        if (R == Resolution::Resolved) {
          InScope.push_back(M.getFunction(N));
        } else {
          // The misspelt-name failure. A record is still written and is well
          // formed; nothing in it is a pin. Said on stderr as well as in the
          // record because a caller that reads neither must at least see it in
          // a build log.
          errs() << "WipePin: target " << N << " " << resolutionName(R) << "\n";
        }
      }
    } else {
      for (Function &F : M)
        if (!F.isDeclaration()) InScope.push_back(&F);
    }

    // --- the module-wide census, for the record only -------------------------
    int64_t ZeroFillInModule = 0;
    for (const Function &F : M)
      if (!F.isDeclaration()) ZeroFillInModule += countZeroFillIn(F);

    // --- the pin -------------------------------------------------------------
    std::vector<Site> Sites;
    Unhandled U;
    int64_t ZeroFillInScope = 0;
    int64_t WouldPin = 0;
    int64_t Pinned = 0;
    LLVMContext &Ctx = M.getContext();

    for (Function *F : InScope) {
      int64_t Ordinal = 0;
      for (BasicBlock &BB : *F) {
        for (Instruction &I : BB) {
          // The atomic element-wise memset is a different intrinsic with a
          // different volatility story (it has no volatile operand at all), so
          // it is counted and left alone.
          if (isa<AtomicMemSetInst>(&I)) {
            U.AtomicMemset++;
            continue;
          }
          if (auto *MS = dyn_cast<MemSetInst>(&I)) {
            if (!isZeroFill(*MS)) {
              U.NonZeroFill++;
              continue;
            }
            ZeroFillInScope++;
            Site S;
            S.Function = F->getName().str();
            S.Index = Ordinal++;
            if (const auto *Len = dyn_cast<ConstantInt>(MS->getLength())) {
              if (Len->getValue().getActiveBits() <= 63) {
                S.HaveLength = true;
                S.LengthBytes = static_cast<int64_t>(Len->getZExtValue());
              }
            }
            S.DestKind = destKindOf(MS->getDest());
            if (const DebugLoc &DL = MS->getDebugLoc()) {
              S.HaveLine = true;
              S.Line = static_cast<int64_t>(DL.getLine());
            }
            if (MS->isVolatile()) {
              S.AlreadyVolatile = true;
            } else {
              WouldPin++;
              if (!C.DryRun) {
                MS->setVolatile(ConstantInt::getTrue(Ctx));
                Pinned++;
              }
            }
            Sites.push_back(std::move(S));
            continue;
          }
          // Wipes this pass does not touch, counted so that "nothing was
          // pinned" can be told apart from "there was nothing to pin".
          if (const auto *CB = dyn_cast<CallBase>(&I)) {
            const Function *Callee = CB->getCalledFunction();
            if (!Callee || Callee->isIntrinsic()) continue;
            const StringRef Name = Callee->getName();
            if (Name == "memset") U.LibcallMemset++;
            else if (Name == "__memset_chk") U.MemsetChk++;
            else if (Name.starts_with("memset.")) U.InlineWrapperMemset++;
          }
        }
      }
    }

    if (C.DryRun && WouldPin > 0)
      errs() << "WipePin: dry run: " << WouldPin
             << " zero-fill llvm.memset site(s) would be pinned; none was "
                "changed\n";
    if (WouldPin == 0 && ZeroFillInScope == 0)
      errs() << "WipePin: nothing to pin in scope in " << ModuleName
             << " (zero-fill llvm.memset in scope: 0; unhandled in scope: "
             << "libcallMemset=" << U.LibcallMemset
             << " memsetChk=" << U.MemsetChk
             << " nonZeroFill=" << U.NonZeroFill
             << " atomicMemset=" << U.AtomicMemset
             << " inlineWrapperMemset=" << U.InlineWrapperMemset << ")\n";

    emit(ModuleName, RequestedJ, ResolutionJ, Sites, Pinned, WouldPin,
         ZeroFillInScope, ZeroFillInModule, U);

    return Pinned > 0 ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

private:
  void emit(const std::string &ModuleName, Json RequestedJ, Json ResolutionJ,
            const std::vector<Site> &Sites, int64_t Pinned, int64_t WouldPin,
            int64_t ZeroFillInScope, int64_t ZeroFillInModule,
            const Unhandled &U) const {
    const Config &C = *Cfg;
    Json R = Json::object();
    R.set("schemaVersion", Json::str("wipe-pin-v0"));
    R.set("component", Json::str("WipePin"));
    R.set("module", Json::str(ModuleName));
    R.set("optLevel",
          Json::object()
              .set("speedup", Json::integer(Level.getSpeedupLevel()))
              .set("size", Json::integer(Level.getSizeLevel())));
    R.set("scope", Json::str(C.S == Scope::Functions ? "functions" : "module"));
    R.set("requested", std::move(RequestedJ));
    R.set("resolution", std::move(ResolutionJ));
    R.set("dryRun", Json::boolean(C.DryRun));

    Json P = Json::array();
    for (const Site &S : Sites) {
      P.push(Json::object()
                 .set("function", Json::str(S.Function))
                 .set("index", Json::integer(S.Index))
                 .set("lengthBytes",
                      S.HaveLength ? Json::integer(S.LengthBytes) : Json::null())
                 .set("destKind", Json::str(S.DestKind))
                 .set("alreadyVolatile", Json::boolean(S.AlreadyVolatile))
                 .set("line", S.HaveLine ? Json::integer(S.Line) : Json::null()));
    }
    R.set("pinned", std::move(P));
    R.set("pinnedCount", Json::integer(Pinned));
    R.set("wouldPinCount", Json::integer(WouldPin));
    R.set("seen", Json::object()
                      .set("zeroFillMemsetInScope", Json::integer(ZeroFillInScope))
                      .set("zeroFillMemsetInModule", Json::integer(ZeroFillInModule)));
    R.set("unhandled", Json::object()
                           .set("libcallMemset", Json::integer(U.LibcallMemset))
                           .set("memsetChk", Json::integer(U.MemsetChk))
                           .set("nonZeroFill", Json::integer(U.NonZeroFill))
                           .set("atomicMemset", Json::integer(U.AtomicMemset))
                           .set("inlineWrapperMemset",
                                Json::integer(U.InlineWrapperMemset)));

    // interfaces.md section 5, as IrCheckpoints applies it: the digest covers
    // everything but `context`, and `context` holds the one thing a re-run
    // cannot reproduce.
    R.set("evidenceDigest", Json::str(Json::digestOf(R)));
    Json Ctx = Json::object();
    const char *SDE = std::getenv("SOURCE_DATE_EPOCH");
    const int64_t When = SDE ? static_cast<int64_t>(std::strtoll(SDE, nullptr, 10))
                             : static_cast<int64_t>(std::time(nullptr));
    Ctx.set("timeSource", Json::str(SDE ? "SOURCE_DATE_EPOCH" : "wall-clock"));
    Ctx.set("sourceDateEpoch", SDE ? Json::integer(When) : Json::null());
    Ctx.set("generatedAt", Json::integer(When));
    R.set("context", std::move(Ctx));

    std::error_code EC;
    raw_fd_ostream Out(C.OutPath, EC, sys::fs::OF_Text);
    if (EC) {
      // The IR has already been changed by the time this runs, so the object
      // file will carry the pin and there will be no record of it. Loud, and
      // pin.sh turns the missing record into exit 3.
      errs() << "WipePin: cannot write the record to WPIN_OUT (" << EC.message()
             << "); the IR was " << (Pinned > 0 ? "changed" : "not changed")
             << " and nothing records it\n";
      return;
    }
    Out << R.serialise() << "\n";
  }

  std::shared_ptr<const Config> Cfg;
  OptimizationLevel Level;
};

} // namespace wpin

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "WipePin", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            wpin::Config Cfg = wpin::loadConfig();
            if (!Cfg.Valid) {
              // Loud, and not an error: failing the compile would only get the
              // plugin removed from the build line, and the caller's wrapper
              // turns "no record" into exit 3 anyway.
              errs() << "WipePin: refusing to install: " << Cfg.Rejected << "\n";
              for (const std::string &N : Cfg.Notes) errs() << N << "\n";
              return;
            }
            for (const std::string &N : Cfg.Notes) errs() << N << "\n";

            auto Shared = std::make_shared<const wpin::Config>(std::move(Cfg));
            PB.registerPipelineStartEPCallback(
                [Shared](ModulePassManager &MPM, OptimizationLevel L) {
                  MPM.addPass(wpin::WipePinPass(Shared, L));
                });
          }};
}
