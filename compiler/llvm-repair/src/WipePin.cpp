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
//
// A pin is not a repair. A zero-fill memset is also what `= {0}` lowers to, and
// what a model writes to clear a buffer BEFORE it fills it; pinning that one
// leaves the real wipe -- often a loop of stores, which this pass cannot see --
// exactly as removable as it was. So every recorded site carries
// `followedByUse`: whether some other instruction touching the same stack
// object can run after it. A pinned site with a later use is initialiser-like,
// and stderr says so (the "partial" line), because a record that only counts
// pins would read that compile as repaired. wipe-pin-v2 changes only how that
// question is answered: an edge of clang's cleanup dispatch that the path being
// followed cannot take no longer counts (CleanupDispatch, below).

#include "PinSelector.h"
#include "Record.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Dominators.h"
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
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <utility>
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

/// `followedByUse`, as a tri-state: the record's true / false / null.
enum class LaterUse { Yes, No, NotAlloca };

/// clang's cleanup dispatch, modelled just far enough to follow the edge a path
/// actually takes through it. New in wipe-pin-v2.
///
/// At -O1 and above clang emits lifetime markers, so a scope that declares a
/// local has a cleanup, and every jump out of that scope -- a `return` inside a
/// loop body, a `break`, a `continue`, falling off the end of the body -- is
/// routed through ONE shared cleanup block. Which way the jump was going is kept
/// in an i32 stack slot (named `cleanup.dest.slot` in a build that keeps value
/// names; unnamed in the release clang measured here): each jump stores its own
/// constant into the slot, the shared block loads it back, and a `switch` on
/// that load sends control on. Measured on fable_N_token_r3.c at -O1, front-end
/// IR: `store i32 1, ptr %7` before `br label %28` on the `return -1` path,
/// `store i32 0, ptr %7` on the fall-through path, and in %28
/// `switch i32 (load %7), label %33 [i32 0, label %30]`, where %30 goes back to
/// the loop header and %33 is the function's exit. The CFG therefore has a path
/// from the error-path memset back into the loop, although no execution takes
/// it: on that path the slot holds 1, and 1 selects %33.
///
/// A slot is modelled only when every one of its users is a non-volatile store
/// INTO it of a ConstantInt of its own type, or a non-volatile load FROM it of
/// its own type: nothing else can write it, nothing can take its address, and
/// its value at any point on a path is the constant last stored on that path.
/// A slot with any other user (a lifetime marker, a GEP, a call, its address
/// stored somewhere) is not modelled, and every switch on it keeps all of its
/// edges. The test is the shape, not clang's slot name (which a release clang
/// discards anyway): a source variable of the same shape switched on directly
/// is modelled too, and for the same reason just as soundly. That is the whole
/// model; anything it does not describe is plain reachability, as in v1.
class CleanupDispatch {
public:
  explicit CleanupDispatch(const Function &F) {
    for (const Instruction &I : F.getEntryBlock()) {
      const auto *AI = dyn_cast<AllocaInst>(&I);
      if (!AI || AI->isArrayAllocation() || !AI->getAllocatedType()->isIntegerTy())
        continue;
      if (onlyConstantStoresAndLoads(*AI)) {
        SlotIndex[AI] = static_cast<unsigned>(Slots.size());
        Slots.push_back(AI);
      }
    }
  }

  /// Whether some instruction in `Uses` can run after `From`, following every
  /// CFG edge except those a modelled switch cannot take on the current path.
  ///
  /// A depth-first search over (block, the last constant stored into each
  /// modelled slot on this path). The state at `From` is "unknown" for every
  /// slot -- the search does not look backwards -- and an unknown slot, or a
  /// switch whose load was not read on the current walk of its own block (the
  /// load sits in another block, or before `From` in `From`'s block), keeps all
  /// successors. `From`'s block is walked from just after `From`, and again in
  /// full if a path comes back to it. Past `MaxStates` (block, state) pairs it
  /// gives up and answers "yes", the direction isPotentiallyReachable gives up
  /// in.
  bool someUseReachable(const Instruction &From,
                        const SmallPtrSetImpl<const Instruction *> &Uses) const {
    using State = std::vector<const ConstantInt *>; // nullptr = unknown
    std::set<std::pair<const BasicBlock *, State>> Visited;
    SmallVector<std::pair<const BasicBlock *, State>, 16> Work;

    // Walks [It, end) of BB under S; true on reaching a use, otherwise pushes
    // the successors this path can take.
    auto Walk = [&](const BasicBlock &BB, BasicBlock::const_iterator It,
                    State S) -> bool {
      DenseMap<const LoadInst *, const ConstantInt *> ReadHere;
      for (; It != BB.end(); ++It) {
        const Instruction &I = *It;
        if (Uses.count(&I)) return true;
        if (const auto *SI = dyn_cast<StoreInst>(&I)) {
          if (const auto *Slot = dyn_cast<AllocaInst>(SI->getPointerOperand())) {
            auto F = SlotIndex.find(Slot);
            if (F != SlotIndex.end())
              S[F->second] = cast<ConstantInt>(SI->getValueOperand());
          }
        } else if (const auto *L = dyn_cast<LoadInst>(&I)) {
          if (const auto *Slot = dyn_cast<AllocaInst>(L->getPointerOperand())) {
            auto F = SlotIndex.find(Slot);
            if (F != SlotIndex.end()) ReadHere[L] = S[F->second];
          }
        }
      }
      const Instruction *T = BB.getTerminator();
      if (const auto *SW = dyn_cast_or_null<SwitchInst>(T)) {
        if (const auto *L = dyn_cast<LoadInst>(SW->getCondition())) {
          auto F = ReadHere.find(L);
          if (F != ReadHere.end() && F->second) {
            // The one edge this path takes. findCaseValue falls back to the
            // default destination when no case matches, as the switch does.
            const BasicBlock *Next =
                SW->findCaseValue(F->second)->getCaseSuccessor();
            Work.emplace_back(Next, S);
            return false;
          }
        }
      }
      for (const BasicBlock *Succ : successors(&BB)) Work.emplace_back(Succ, S);
      return false;
    };

    if (Walk(*From.getParent(), std::next(From.getIterator()),
             State(Slots.size(), nullptr)))
      return true;
    while (!Work.empty()) {
      auto Item = Work.pop_back_val();
      if (!Visited.insert(Item).second) continue;
      if (Visited.size() > MaxStates) return true;
      if (Walk(*Item.first, Item.first->begin(), Item.second)) return true;
    }
    return false;
  }

private:
  static bool onlyConstantStoresAndLoads(const AllocaInst &AI) {
    Type *Ty = AI.getAllocatedType();
    for (const User *U : AI.users()) {
      if (const auto *SI = dyn_cast<StoreInst>(U)) {
        if (SI->getPointerOperand() != &AI || SI->isVolatile() ||
            !isa<ConstantInt>(SI->getValueOperand()) ||
            SI->getValueOperand()->getType() != Ty)
          return false;
        continue;
      }
      if (const auto *LI = dyn_cast<LoadInst>(U)) {
        if (LI->isVolatile() || LI->getType() != Ty) return false;
        continue;
      }
      return false;
    }
    return true;
  }

  /// A bound on the search, not a tuning knob: it keeps a pathological function
  /// from stalling the compile, and reaching it answers "yes". How close any
  /// search in the corpus came to it was not measured.
  static constexpr size_t MaxStates = 1u << 16;

  std::vector<const AllocaInst *> Slots;
  DenseMap<const AllocaInst *, unsigned> SlotIndex;
};

/// Whether some instruction other than `MS` that uses the stack object `MS`
/// writes can run after `MS`.
///
/// The object is getUnderlyingObject(dest). When that is not an AllocaInst --
/// a parameter, a global, a pointer loaded from memory -- the question has no
/// answer here (the buffer outlives the function, or its other uses are not in
/// this function) and the result is NotAlloca, recorded as null.
///
/// Uses are followed from the alloca through GEP, bitcast and addrspacecast,
/// and also through phi and select, which carry the same pointer on. Stores
/// into stack slots are followed too: when the address is stored into a slot
/// (`unsigned char *p = key;`), every load from that slot is treated as the
/// address again -- and so on, for whatever those loads are stored into -- so
/// `memset(key, ...); use(p);` is seen. That is all: an address stored anywhere
/// else, or into a slot reached through a GEP, is not followed, and a use made
/// through it is missed. (A slot that is later given another pointer makes its
/// loads count all the same: that errs towards "yes".) llvm.lifetime.* and
/// debug intrinsics are not uses, and neither is `MS` itself. Another memset
/// into the same buffer is a use: it is an instruction touching the object, and
/// the question is whether this site is the buffer's last word.
///
/// Reachability is asked twice, and the second question can only take a "yes"
/// back, never add one:
///
///   1. llvm::isPotentiallyReachable, instruction to instruction, exactly as in
///      wipe-pin-v1. It answers "yes" when it cannot tell (it gives up after a
///      bounded number of blocks). A "no" here is final.
///   2. Only when (1) said "yes": the same question through CleanupDispatch,
///      which follows every edge except the ones clang's cleanup dispatch
///      cannot take on the path being followed. A "no" here means every CFG
///      path from `MS` to every use goes through a modelled switch edge that is
///      infeasible on it; that, and only that, turns v1's "yes" into "no".
///
/// A "yes" that is really "don't know" makes the partial line appear where it
/// may not be needed; it can never hide one. A wrong "no" would hide one, which
/// is why (2) models one front-end shape exactly and nothing near it.
///
/// Computed at pipeline start, on the IR as the front end wrote it, before this
/// pass mutates anything.
LaterUse laterUseOf(const MemSetInst &MS, const DominatorTree &DT,
                    const LoopInfo &LI, const CleanupDispatch &CD) {
  const auto *AI = dyn_cast<AllocaInst>(getUnderlyingObject(MS.getDest()));
  if (!AI) return LaterUse::NotAlloca;

  // Every use, collected in full (v1 stopped at the first reachable one; the
  // second question needs them all). The same walk, the same uses.
  SmallPtrSet<const Instruction *, 16> Uses;
  SmallVector<const Value *, 16> Work;
  SmallPtrSet<const Value *, 16> Seen;
  Work.push_back(AI);
  Seen.insert(AI);
  while (!Work.empty()) {
    const Value *V = Work.pop_back_val();
    for (const User *U : V->users()) {
      const auto *I = dyn_cast<Instruction>(U);
      if (!I || I == &MS) continue;
      if (isa<GetElementPtrInst>(I) || isa<BitCastInst>(I) ||
          isa<AddrSpaceCastInst>(I) || isa<PHINode>(I) || isa<SelectInst>(I)) {
        if (Seen.insert(I).second) Work.push_back(I);
        continue;
      }
      if (const auto *II = dyn_cast<IntrinsicInst>(I))
        if (II->isLifetimeStartOrEnd() || isa<DbgInfoIntrinsic>(II)) continue;
      if (const auto *SI = dyn_cast<StoreInst>(I)) {
        if (SI->getValueOperand() == V) {
          if (const auto *Slot = dyn_cast<AllocaInst>(
                  SI->getPointerOperand()->stripPointerCasts())) {
            for (const User *SU : Slot->users())
              if (const auto *Reload = dyn_cast<LoadInst>(SU))
                if (Seen.insert(Reload).second) Work.push_back(Reload);
          }
        }
        // The store itself is still a use, and is checked below like any
        // other: storing the address after the memset hands the buffer on.
      }
      Uses.insert(I);
    }
  }

  bool Reachable = false;
  for (const Instruction *I : Uses)
    if (isPotentiallyReachable(&MS, I, nullptr, &DT, &LI)) {
      Reachable = true;
      break;
    }
  if (!Reachable) return LaterUse::No;
  return CD.someUseReachable(MS, Uses) ? LaterUse::Yes : LaterUse::No;
}

/// LLVM's own spelling of a linkage, as it appears in textual IR. Hand-written
/// because the table AsmWriter keeps is not exported.
const char *linkageName(GlobalValue::LinkageTypes L) {
  switch (L) {
  case GlobalValue::ExternalLinkage: return "external";
  case GlobalValue::AvailableExternallyLinkage: return "available_externally";
  case GlobalValue::LinkOnceAnyLinkage: return "linkonce";
  case GlobalValue::LinkOnceODRLinkage: return "linkonce_odr";
  case GlobalValue::WeakAnyLinkage: return "weak";
  case GlobalValue::WeakODRLinkage: return "weak_odr";
  case GlobalValue::AppendingLinkage: return "appending";
  case GlobalValue::InternalLinkage: return "internal";
  case GlobalValue::PrivateLinkage: return "private";
  case GlobalValue::ExternalWeakLinkage: return "extern_weak";
  case GlobalValue::CommonLinkage: return "common";
  }
  return "unknown";
}

/// interfaces.md section 5 requires every record to carry, outside `context`,
/// `toolchain: {digest, clang, packages}`. This is the block
/// IrCheckpoints::toolchainJson (compiler/llvm-pass/src/IrCheckpoints.cpp)
/// writes, built the same way from the same source: LLVM_VERSION_STRING of the
/// headers the plugin was compiled against, a one-entry package list naming
/// llvm, and a digest that is the SHA-256 of the canonical serialisation of
/// {clang, packages}. Rewritten rather than shared because that one is a private
/// member of a class in a file this component does not compile; the shape and
/// the recipe are the same, and the fixture-loop checker re-derives the digest.
Json toolchainJson() {
  Json Pkgs = Json::array();
  Pkgs.push(Json::object()
                .set("name", Json::str("llvm"))
                .set("version", Json::str(LLVM_VERSION_STRING)));
  Json T = Json::object();
  T.set("clang", Json::str(LLVM_VERSION_STRING));
  T.set("packages", std::move(Pkgs));
  Json ForDigest = Json::object();
  ForDigest.set("clang", Json::str(LLVM_VERSION_STRING));
  ForDigest.set("packages",
                Json::array().push(Json::object()
                                       .set("name", Json::str("llvm"))
                                       .set("version", Json::str(LLVM_VERSION_STRING))));
  T.set("digest", Json::str(irck::sha256Hex(ForDigest.serialise())));
  return T;
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
  LaterUse FollowedByUse = LaterUse::NotAlloca;
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
        Json Entry = Json::object()
                         .set("name", Json::str(N))
                         .set("resolution", Json::str(resolutionName(R)));
        if (R == Resolution::Resolved) {
          Function *F = M.getFunction(N);
          // A definition that is not exact -- linkonce_odr (a C++ inline or
          // template function), weak, available_externally (a C99 inline
          // definition, emitted only when optimising) -- is one the linker or
          // the optimiser may replace with another translation unit's copy, or
          // drop. The pin is applied to this copy all the same; whether this
          // copy is the one that runs is not something this unit can know.
          const bool Exact = F->isDefinitionExact();
          const char *Linkage = linkageName(F->getLinkage());
          Entry.set("exact", Json::boolean(Exact));
          Entry.set("linkage", Json::str(Linkage));
          if (!Exact)
            errs() << "WipePin: target " << N << " is not an exact definition ("
                   << Linkage << "); the copy that runs may come from another "
                                 "translation unit\n";
          InScope.push_back(F);
        } else {
          Entry.set("exact", Json::null());
          Entry.set("linkage", Json::null());
          // The misspelt-name failure. A record is still written and is well
          // formed; nothing in it is a pin. Said on stderr as well as in the
          // record because a caller that reads neither must at least see it in
          // a build log.
          errs() << "WipePin: target " << N << " " << resolutionName(R) << "\n";
        }
        ResolutionJ.push(std::move(Entry));
      }
    } else {
      for (Function &F : M)
        if (!F.isDeclaration()) InScope.push_back(&F);
    }

    // --- the module-wide census, for the record only -------------------------
    int64_t ZeroFillInModule = 0;
    for (const Function &F : M)
      if (!F.isDeclaration()) ZeroFillInModule += countZeroFillIn(F);

    // --- the census: every site, read before anything is changed -------------
    std::vector<Site> Sites;
    std::vector<MemSetInst *> ToPin;
    Unhandled U;
    int64_t ZeroFillInScope = 0;
    int64_t WouldPin = 0;
    int64_t Pinned = 0;
    LLVMContext &Ctx = M.getContext();

    for (Function *F : InScope) {
      int64_t Ordinal = 0;
      // Built on the unmodified function. Setting a volatile flag changes no
      // block and no use, but nothing is changed until every site of every
      // function in scope has been read, so that no answer depends on that.
      const DominatorTree DT(*F);
      const LoopInfo LI(DT);
      const CleanupDispatch CD(*F);
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
            S.FollowedByUse = laterUseOf(*MS, DT, LI, CD);
            if (const DebugLoc &DL = MS->getDebugLoc()) {
              S.HaveLine = true;
              S.Line = static_cast<int64_t>(DL.getLine());
            }
            if (MS->isVolatile()) {
              S.AlreadyVolatile = true;
            } else {
              WouldPin++;
              ToPin.push_back(MS);
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

    // --- the pin -------------------------------------------------------------
    if (!C.DryRun) {
      for (MemSetInst *MS : ToPin) {
        MS->setVolatile(ConstantInt::getTrue(Ctx));
        Pinned++;
      }
    }

    const std::string UnhandledText =
        "libcallMemset=" + std::to_string(U.LibcallMemset) +
        " memsetChk=" + std::to_string(U.MemsetChk) +
        " nonZeroFill=" + std::to_string(U.NonZeroFill) +
        " atomicMemset=" + std::to_string(U.AtomicMemset) +
        " inlineWrapperMemset=" + std::to_string(U.InlineWrapperMemset);
    const bool AnyUnhandled = U.LibcallMemset > 0 || U.MemsetChk > 0 ||
                              U.NonZeroFill > 0 || U.AtomicMemset > 0 ||
                              U.InlineWrapperMemset > 0;
    int64_t FollowedByUse = 0;
    for (const Site &S : Sites)
      if (S.FollowedByUse == LaterUse::Yes) FollowedByUse++;

    if (C.DryRun && WouldPin > 0)
      errs() << "WipePin: dry run: " << WouldPin
             << " zero-fill llvm.memset site(s) would be pinned; none was "
                "changed\n";
    if (WouldPin == 0 && ZeroFillInScope == 0)
      errs() << "WipePin: nothing to pin in scope in " << ModuleName
             << " (zero-fill llvm.memset in scope: 0; unhandled in scope: "
             << UnhandledText << ")\n";
    // The partial repair. Either a recorded site is followed by a later use of
    // its buffer -- so it is an initialiser or a clear-before-fill, and pinning
    // it says nothing about the wipe -- or something was pinned while a
    // memset-shaped call in the same scope was left alone. In both cases the
    // record's pinnedCount is positive and the compile looks repaired; this
    // line is what keeps a build log from agreeing.
    if (FollowedByUse > 0 || (Pinned > 0 && AnyUnhandled))
      errs() << "WipePin: partial: pinned " << Pinned << " site(s) in "
             << ModuleName << "; " << FollowedByUse
             << " followed by a later use of the same buffer (initialiser-like, "
                "not a wipe); unhandled in scope: "
             << UnhandledText << "\n";

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
    R.set("schemaVersion", Json::str("wipe-pin-v2"));
    R.set("component", Json::str("WipePin"));
    R.set("module", Json::str(ModuleName));
    R.set("toolchain", toolchainJson());
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
                 .set("followedByUse",
                      S.FollowedByUse == LaterUse::NotAlloca
                          ? Json::null()
                          : Json::boolean(S.FollowedByUse == LaterUse::Yes))
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
            // First, before any refusal: clear what an earlier compile left at
            // WPIN_OUT. This callback runs when clang loads the plugin, which
            // it does even under -Xclang -disable-llvm-passes, where the pass
            // itself never runs -- so in that compile, and in a refused one,
            // "no record" is the truth about this compile rather than an old
            // record standing in for it.
            std::string Why;
            if (!wpin::clearStaleRecord(Why)) {
              errs() << "WipePin: refusing to install: " << Why << "\n";
              return;
            }
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
