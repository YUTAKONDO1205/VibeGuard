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
// leaves the real wipe -- often a loop of stores, which the pin cannot see --
// exactly as removable as it was. So every recorded site carries
// `followedByUse`: whether some other instruction touching the same stack
// object can run after it. A pinned site with a later use is initialiser-like,
// and stderr says so (the "partial" line), because a record that only counts
// pins would read that compile as repaired. wipe-pin-v2 changes only how that
// question is answered: an edge of clang's cleanup dispatch that the path being
// followed cannot take no longer counts (CleanupDispatch, below).
//
// Loaded into a pipeline that never runs pipeline start -- an LTO link's, full
// or thin, at any level -- the pass is never added, so it never runs, never
// writes a record, and pins nothing; but the load-time callback has already
// removed whatever was at WPIN_OUT, which in a build that exports WPIN_* to
// every step is the record its compile step wrote. That used to happen with rc
// 0 and nothing on stderr. Now the first pass such a pipeline runs makes the
// plugin say so, once per process (sayIfNoPipelineStart, below). It is a pass
// instrumentation callback, not a pass: it reads three flags and prints; it
// never sees or touches the IR, and it writes no record.
//
// wipe-pin-v3 (../schema/wipe-pin.md section 14) adds three things, all off by
// default, and a check that is always on:
//
//   - WPIN_BARRIER_CALLS=1: a zero-fill memset or bzero that reaches pipeline
//     start as a call (the -D_FORTIFY_SOURCE wrapper memset.inline,
//     __memset_chk, a libcall memset, bzero) gets an empty asm barrier that
//     reads its destination, right after the call (BarrierSite, below);
//   - WPIN_ZERO_COPY=1: a copy from an all-zero constant global is repaired --
//     llvm.memcpy replaced by a volatile llvm.memset (llvm.memcpy.inline by a
//     volatile llvm.memset.inline), a memcpy call given the same barrier
//     (ZeroCopySite, below);
//   - WPIN_BUFFER_BARRIER=1: a stack buffer that some zero fill writes -- a
//     memset, a loop of zero stores, a copy from an all-zero constant -- and
//     that is not only initialised gets an empty asm barrier that reads it
//     directly before each of its llvm.lifetime.end calls, or, when it has
//     none, before each reachable `ret` the buffer dominates (before the
//     musttail call, when the `ret` follows one) (BufferSite, below);
//   - the version handshake: before it reads anything else, the pass compares
//     the module's producer, the module's intrinsic numbering and the host's
//     own intrinsic table with the LLVM this plugin was built against, and
//     refuses on a difference (checkHost, below).
//
// With the three variables unset, the code emitted is meant to be exactly what
// the v2 plugin emitted; the record says so with three blocks that read
// enabled: false. The fixture loop compares the -S output with the v2 build's.

#include "PinSelector.h"
#include "Record.h"

#include "llvm/ADT/Any.h"
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
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <atomic>
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

/// `S` begins with `P`. Spelled out so that one source builds against LLVM 15
/// to 20: StringRef::starts_with first appears in 16, and the older startswith
/// is gone from 19.
bool hasPrefix(StringRef S, StringRef P) {
  return S.size() >= P.size() && S.substr(0, P.size()) == P;
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
///
/// laterUseFrom is the walk, from any instruction `Site` that writes the stack
/// object `AIRef`: the buffer barrier (below) asks the same question of a zero
/// store in a loop and of a zero copy, not only of a memset. laterUseOf is the
/// memset's form of it, and what pinned[].followedByUse records.
///
/// collectUses is the use collection the walk starts from, shared with the
/// buffer barrier's second question (useWithinLifetime, below).
void collectUses(const AllocaInst &AI, const Instruction &MS,
                 SmallPtrSetImpl<const Instruction *> &Uses) {
  SmallVector<const Value *, 16> Work;
  SmallPtrSet<const Value *, 16> Seen;
  Work.push_back(&AI);
  Seen.insert(&AI);
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
}

LaterUse laterUseFrom(const Instruction &Site, const AllocaInst &AIRef,
                      const DominatorTree &DT, const LoopInfo &LI,
                      const CleanupDispatch &CD) {
  const AllocaInst *AI = &AIRef;
  const Instruction &MS = Site;

  // Every use, collected in full (v1 stopped at the first reachable one; the
  // second question needs them all). The same walk, the same uses.
  SmallPtrSet<const Instruction *, 16> Uses;
  collectUses(*AI, MS, Uses);

  bool Reachable = false;
  for (const Instruction *I : Uses)
    if (isPotentiallyReachable(&MS, I, nullptr, &DT, &LI)) {
      Reachable = true;
      break;
    }
  if (!Reachable) return LaterUse::No;
  return CD.someUseReachable(MS, Uses) ? LaterUse::Yes : LaterUse::No;
}

LaterUse laterUseOf(const MemSetInst &MS, const DominatorTree &DT,
                    const LoopInfo &LI, const CleanupDispatch &CD) {
  const auto *AI = dyn_cast<AllocaInst>(getUnderlyingObject(MS.getDest()));
  if (!AI) return LaterUse::NotAlloca;
  return laterUseFrom(MS, *AI, DT, LI, CD);
}

/// Whether `I` ends or restarts the lifetime of the stack object `AI`: an
/// llvm.lifetime.end or llvm.lifetime.start of it, or the alloca itself, which
/// makes a new object each time it runs (a variable-length array declared in a
/// loop body; a static alloca sits in the entry block, which no path re-enters).
bool endsLifetimeOf(const Instruction &I, const AllocaInst &AI) {
  if (&I == &AI) return true;
  if (const auto *II = dyn_cast<IntrinsicInst>(&I))
    if (II->isLifetimeStartOrEnd() &&
        getUnderlyingObject(II->getArgOperand(II->arg_size() - 1)) == &AI)
      return true;
  return false;
}

/// The buffer barrier's second question, new with the barrier: whether some
/// instruction in `Uses` can run after `Site` on a CFG path that does not end
/// or restart the object's lifetime first (endsLifetimeOf). A use reached only
/// across the end of the lifetime is a use of another lifetime of the same
/// alloca -- the next iteration's buffer, for one declared in a loop body and
/// wiped at the end of each iteration, which laterUseFrom alone reads as a
/// later use of the same buffer and so as an initialiser. Every CFG edge is
/// taken, as by isPotentiallyReachable; nothing else is pruned. clang emits no
/// lifetime markers at -O0, so there this answers as plain reachability does.
bool useWithinLifetime(const Instruction &Site, const AllocaInst &AI,
                       const SmallPtrSetImpl<const Instruction *> &Uses) {
  // 1 = reached a use, 0 = the lifetime ended first, -1 = reached the end.
  auto Walk = [&](BasicBlock::const_iterator It,
                  BasicBlock::const_iterator End) -> int {
    for (; It != End; ++It) {
      if (Uses.count(&*It)) return 1;
      if (endsLifetimeOf(*It, AI)) return 0;
    }
    return -1;
  };
  SmallPtrSet<const BasicBlock *, 32> Visited;
  SmallVector<const BasicBlock *, 32> Work;
  const BasicBlock *First = Site.getParent();
  // Site's block is walked from just after Site, and again in full if a path
  // comes back to it.
  const int R = Walk(std::next(Site.getIterator()), First->end());
  if (R == 1) return true;
  if (R == -1)
    for (const BasicBlock *S : successors(First)) Work.push_back(S);
  while (!Work.empty()) {
    const BasicBlock *BB = Work.pop_back_val();
    if (!Visited.insert(BB).second) continue;
    const int W = Walk(BB->begin(), BB->end());
    if (W == 1) return true;
    if (W == 0) continue;
    for (const BasicBlock *S : successors(BB)) Work.push_back(S);
  }
  return false;
}

/// "Is this zero fill followed by a later use of the buffer?", as the buffer
/// barrier asks it: yes only when laterUseFrom says yes AND useWithinLifetime
/// does. Both over-approximate the paths (each follows CFG paths no execution
/// may take), so on the paths their conjunction errs towards "yes", i.e.
/// towards calling a wipe an initialiser and placing no barrier -- the
/// direction that leaves the program as stock compiles it, and that stderr then
/// counts. On the uses they do not: an address stored into memory other than a
/// pointer slot (a field of a local struct, say) is not followed (collectUses),
/// so an initialiser used afterwards only through such a copy reads as a wipe
/// and gets a barrier.
LaterUse bufferLaterUse(const Instruction &Site, const AllocaInst &AI,
                        const DominatorTree &DT, const LoopInfo &LI,
                        const CleanupDispatch &CD) {
  const LaterUse Walked = laterUseFrom(Site, AI, DT, LI, CD);
  if (Walked != LaterUse::Yes) return Walked;
  SmallPtrSet<const Instruction *, 16> Uses;
  collectUses(AI, Site, Uses);
  // A store that only advances a pointer held in a stack slot -- the slot's
  // own value, reloaded, offset and written back, as `*p++ = 0` does -- moves
  // the pointer and touches no byte of the buffer, so it is not a use here.
  // laterUseFrom counts it (the address handed on), which is why a wipe
  // written through `p++` read as an initialiser before this.
  // A comparison of the buffer's address -- the bound of a loop that walks a
  // pointer up to the buffer's end, `for (p = key; p < key + n; p++) *p = 0`
  // -- reads no byte of the buffer either, so it is not a use here.
  SmallVector<const Instruction *, 8> Advances;
  for (const Instruction *I : Uses) {
    if (isa<ICmpInst>(I)) {
      Advances.push_back(I);
      continue;
    }
    if (const auto *SI = dyn_cast<StoreInst>(I))
      if (const auto *Slot =
              dyn_cast<AllocaInst>(SI->getPointerOperand()->stripPointerCasts()))
        if (const auto *Back =
                dyn_cast<LoadInst>(getUnderlyingObject(SI->getValueOperand())))
          if (Back->getPointerOperand()->stripPointerCasts() == Slot)
            Advances.push_back(I);
  }
  for (const Instruction *I : Advances) Uses.erase(I);
  return useWithinLifetime(Site, AI, Uses) ? LaterUse::Yes : LaterUse::No;
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
  /// A call or invoke of `bzero`, and of `bzero.<suffix>` -- the name clang
  /// would give a gnu_inline bzero wrapper, as it gives memset's
  /// `memset.inline`. Left alone (and counted) unless WPIN_BARRIER_CALLS
  /// repairs it.
  int64_t BzeroCall = 0;
  int64_t InlineWrapperBzero = 0;
  /// A copy from an all-zero constant global, left alone because
  /// WPIN_ZERO_COPY is off: as a non-volatile llvm.memcpy, and as a call or
  /// invoke of memcpy, __memcpy_chk or memcpy.<suffix> (an invoke stays here
  /// with the switch on: only a plain call gets the barrier).
  int64_t ZeroGlobalCopy = 0;
  int64_t ZeroGlobalCopyCall = 0;
};

/// A zero-fill memset that reaches pipeline start as a call, not the intrinsic,
/// and that WPIN_BARRIER_CALLS repairs. Measured shape (clang 18.1.3, glibc,
/// -D_FORTIFY_SOURCE=2 and =3; the fixture loop's v3-fort2 and v3-fort3
/// cells): `call ptr @memset.inline(ptr %buf, i32 0, i64 N)`. The wrapper is
/// inlined later, its __memset_chk is folded to llvm.memset once the object
/// size is known, and DSE then deletes it -- all after this pass has run, so
/// there is no intrinsic here to make volatile.
///
/// The repair is the one gcc-repair applies to every wipe: right after the
/// call, an empty `asm volatile` that takes the destination pointer as an input
/// and clobbers memory (the Linux kernel's barrier_data). The optimiser must
/// assume the asm reads the buffer, so the stores before it are not dead. The
/// call itself is left as it is, so the fortify check in the wrapper stays.
struct BarrierSite {
  std::string Function;
  std::string Callee;
  bool HaveLength = false;
  int64_t LengthBytes = 0;
  bool HaveLine = false;
  int64_t Line = 0;
};

bool isZeroValue(const Value *V) {
  const auto *CI = dyn_cast<ConstantInt>(V);
  return CI && CI->isZero();
}

void insertBarrierAfter(CallInst &Call) {
  Value *Dest = Call.getArgOperand(0);
  LLVMContext &Ctx = Call.getContext();
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {Dest->getType()}, false);
  InlineAsm *IA = InlineAsm::get(FT, "", "r,~{memory}", /*hasSideEffects=*/true);
  IRBuilder<> B(Call.getNextNode());
  CallInst *Bar = B.CreateCall(FT, IA, {Dest});
  Bar->setDebugLoc(Call.getDebugLoc());
}

/// WPIN_ZERO_COPY. A wipe written as a copy from an all-zero constant:
/// memcpy(p, vg_zeros, n) with `static const unsigned char vg_zeros[65536];`,
/// a rewrite of the corpus wipes that neither the pin nor the barrier on
/// memset-shaped calls repaired. At pipeline start clang has
/// `llvm.memcpy(p, @vg_zeros, n)`, or under -D_FORTIFY_SOURCE
/// `call @memcpy.inline(p, @vg_zeros, n)` (measured, clang 18.1.3; the fixture
/// loop's v3-zcopy and v3-zcopy-fort2 cells). Later passes turn a copy from a
/// constant zero into a memset and DSE deletes it: the loss of a memset wipe,
/// reached one step later, and with no memset at pipeline start for the pin to
/// mark.
///
/// The source counts only when its underlying object is a GlobalVariable that
/// is constant, whose initializer is definitive (not replaceable at link time)
/// and is the null value. A writable global that happens to hold zeros, or a
/// constant that is not all zero, is not this shape and is not touched.
const GlobalVariable *zeroConstantSource(const Value *Src) {
  const auto *GV = dyn_cast<GlobalVariable>(getUnderlyingObject(Src));
  if (!GV || !GV->isConstant() || !GV->hasDefinitiveInitializer()) return nullptr;
  return GV->getInitializer()->isNullValue() ? GV : nullptr;
}

struct ZeroCopySite {
  std::string Function;
  std::string Form;   // "intrinsic" (llvm.memcpy) or "call"
  std::string Callee; // "llvm.memcpy", or the called function's name
  std::string Source; // the constant global copied from
  std::string DestKind;
  bool HaveLength = false;
  int64_t LengthBytes = 0;
  bool HaveLine = false;
  int64_t Line = 0;
};

ZeroCopySite zeroCopySite(const Function &F, StringRef Form, StringRef Callee,
                          const GlobalVariable &GV, const Value *Dest,
                          const Value *Len, const DebugLoc &DL) {
  ZeroCopySite S;
  S.Function = F.getName().str();
  S.Form = Form.str();
  S.Callee = Callee.str();
  S.Source = GV.getName().str();
  S.DestKind = destKindOf(Dest);
  if (const auto *L = dyn_cast<ConstantInt>(Len)) {
    if (L->getValue().getActiveBits() <= 63) {
      S.HaveLength = true;
      S.LengthBytes = static_cast<int64_t>(L->getZExtValue());
    }
  }
  if (DL) {
    S.HaveLine = true;
    S.Line = static_cast<int64_t>(DL.getLine());
  }
  return S;
}

/// The intrinsic form: the copy becomes a volatile llvm.memset of the same
/// destination, length and destination alignment. For a length within the
/// global the bytes written are the same; a longer one would have read past
/// the global, which the program could not do either. Volatile, so that no
/// later pass may delete it -- the pin WipePin puts on a memset wipe.
///
/// llvm.memcpy.inline (`__builtin_memcpy_inline`) promises that no library
/// call is emitted for it, which code built -ffreestanding may rely on, so it
/// becomes llvm.memset.inline, which promises the same; the plain form could
/// be lowered to a call of memset. Its length is a constant, as memset.inline
/// requires. The record's callee stays "llvm.memcpy" (section 14.9 C7).
void replaceWithVolatileMemset(MemCpyInst &MC) {
  IRBuilder<> B(&MC);
  CallInst *MS =
      isa<MemCpyInlineInst>(&MC)
          ? B.CreateMemSetInline(MC.getRawDest(), MC.getDestAlign(), B.getInt8(0),
                                 MC.getLength(), /*IsVolatile=*/true)
          : B.CreateMemSet(MC.getRawDest(), B.getInt8(0), MC.getLength(),
                           MC.getDestAlign(), /*isVolatile=*/true);
  MS->setDebugLoc(MC.getDebugLoc());
  MC.eraseFromParent();
}

// --- the buffer barrier (WPIN_BUFFER_BARRIER, ../schema/wipe-pin.md 14.6) ---
//
// Every repair above acts at the wipe: it marks the memset, or puts a barrier
// right after a call or a copy. A wipe written as a loop of stores (`for (...)
// p[i] = 0;`) has neither at pipeline start -- loop idiom recognition makes it
// a memset only later, and DSE deletes that -- so no repair above reaches it
// (../eval/repair-loop/pin-families.json, wipe-written-as-stores).
//
// The buffer barrier acts at the other end: the end of the buffer's lifetime.
// Directly before each llvm.lifetime.end of a stack buffer that some zero fill
// writes, it puts `call void asm sideeffect "", "r,~{memory}"(ptr %buf)`: the
// same opaque read insertBarrierAfter uses, but of the whole buffer, at the
// last moment it exists. Whatever the last stores into the buffer were -- a
// memset, a loop of stores, a copy -- the optimiser must assume this asm reads
// them, so they are not dead.
//
// The places are the points where a wipe's path leaves the buffer's lifetime:
// a reachable lifetime.end, or a reachable `ret` -- the only kind there is for
// a buffer with no lifetime.end (every buffer at -O0, and a variable-length
// array at every level), and the kind a scope that ends in a musttail call
// needs at every level. When the `ret` follows a musttail call, the barrier
// goes before the call: nothing may stand between the two. A buffer whose wipe
// reaches a `ret` its alloca does not dominate (an alloca inside a branch or a
// loop; a read of it there would be invalid IR), or a block that ends in
// `unreachable`, gets no barrier at all, and stderr counts it (the census in
// runOnModule says why). So does a buffer whose every zero fill is followed by a later use of it
// in the same lifetime (bufferLaterUse): its last stores are the initialised
// secret, not a wipe, and a barrier would only keep them in memory.
//
// The asm writes nothing, but placing it is not free of effects: the buffer
// must stay in memory (SROA cannot split it), which can change inlining,
// register allocation and the frame, and a buffer that stock kept in registers
// is then written to the stack. Measured, not assumed: README.md, "The buffer
// barrier".
//
// It also stands between the stores and the lifetime.end in the selection
// DAG, where (estimated, not read in LLVM's source: DAGCombiner's
// visitLIFETIME_END) a store directly followed by the end of its object's
// lifetime is dropped.

/// The stack buffer of this function a pointer points into: the AllocaInst
/// under `P`, or -- for a pointer reloaded from a stack slot, the pre-SROA
/// shape of `unsigned char *p = buf; ... p[i] = 0;` -- the one alloca every
/// pointer stored into that slot points into. A store into the slot of the
/// slot's own value, reloaded and advanced (`*p++ = 0`: the reload, a GEP of
/// it, stored back), keeps the slot pointing into the same alloca and is
/// allowed. Any other user of the slot (its address taken, a store of
/// something else) and the answer is "none".
const AllocaInst *bufferAllocaOf(const Value *P) {
  const Value *UO = getUnderlyingObject(P);
  if (const auto *AI = dyn_cast<AllocaInst>(UO)) return AI;
  const auto *Reload = dyn_cast<LoadInst>(UO);
  if (!Reload) return nullptr;
  const auto *Slot =
      dyn_cast<AllocaInst>(Reload->getPointerOperand()->stripPointerCasts());
  if (!Slot) return nullptr;
  const AllocaInst *Found = nullptr;
  for (const User *U : Slot->users()) {
    if (const auto *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getPointerOperand()->stripPointerCasts() != Slot) return nullptr;
      const Value *Stored = getUnderlyingObject(SI->getValueOperand());
      if (const auto *Back = dyn_cast<LoadInst>(Stored))
        if (Back->getPointerOperand()->stripPointerCasts() == Slot) continue;
      const auto *A = dyn_cast<AllocaInst>(Stored);
      if (!A || A == Slot || (Found && Found != A)) return nullptr;
      Found = A;
      continue;
    }
    if (isa<LoadInst>(U)) continue;
    if (const auto *II = dyn_cast<IntrinsicInst>(U))
      if (II->isLifetimeStartOrEnd() || isa<DbgInfoIntrinsic>(II)) continue;
    return nullptr;
  }
  return Found;
}

/// A buffer a zero store in a loop may be the wipe of: an array or struct, or
/// a variable-length alloca. A scalar local zeroed in a loop is a loop counter
/// or a flag far more often than a secret, and a barrier on it would keep it
/// out of a register for nothing.
bool isAggregateBuffer(const AllocaInst &AI) {
  return AI.isArrayAllocation() || AI.getAllocatedType()->isAggregateType();
}

bool isZeroConstant(const Value *V) {
  const auto *K = dyn_cast<Constant>(V);
  return K && K->isNullValue();
}

enum class FillReason { Memset, LoopStore, ZeroCopy };

const char *fillReasonName(FillReason R) {
  switch (R) {
  case FillReason::Memset: return "memset";
  case FillReason::LoopStore: return "loop-store";
  case FillReason::ZeroCopy: return "zero-copy";
  }
  return "memset";
}

/// One entry of the record's bufferBarriers.sites (wipe-pin.md section 14.6).
struct BufferSite {
  std::string Function;
  bool HaveBuffer = false;
  std::string Buffer;      // bufferNameOf; the record says null when absent
  bool HaveBytes = false;
  int64_t Bytes = 0;
  FillReason Reason = FillReason::Memset;
  std::string Anchor;      // "lifetime-end" or "ret"
};

/// The `buffer` of section 14.6: the variable a debug declaration names for the
/// alloca, else the alloca's IR name. False when there is neither -- the usual
/// case without -g, since a release clang discards IR value names unless
/// -fno-discard-value-names is given.
bool bufferNameOf(AllocaInst &AI, std::string &Out) {
#if LLVM_VERSION_MAJOR >= 18
  for (DbgDeclareInst *D : findDbgDeclares(&AI))
#else
  for (DbgDeclareInst *D : FindDbgDeclareUses(&AI))
#endif
    if (const DILocalVariable *V = D->getVariable())
      if (!V->getName().empty()) {
        Out = V->getName().str();
        return true;
      }
#if LLVM_VERSION_MAJOR >= 19
  // The debug-record form of the same declaration (on by default from 19).
  for (DbgVariableRecord *R : findDVRDeclares(&AI))
    if (const DILocalVariable *V = R->getVariable())
      if (!V->getName().empty()) {
        Out = V->getName().str();
        return true;
      }
#endif
#if LLVM_VERSION_MAJOR >= 16
  // With assignment tracking (clang's default at -O1 and above from 17) the
  // alloca has no declaration; the variable is on the dbg.assign markers
  // linked to it by its DIAssignID.
  for (DbgAssignIntrinsic *D : at::getAssignmentMarkers(&AI))
    if (const DILocalVariable *V = D->getVariable())
      if (!V->getName().empty()) {
        Out = V->getName().str();
        return true;
      }
#endif
#if LLVM_VERSION_MAJOR >= 19
  for (DbgVariableRecord *R : at::getDVRAssignmentMarkers(&AI))
    if (const DILocalVariable *V = R->getVariable())
      if (!V->getName().empty()) {
        Out = V->getName().str();
        return true;
      }
#endif
  if (AI.hasName()) {
    Out = AI.getName().str();
    return true;
  }
  return false;
}

/// The barrier, directly before `At`, reading `Buf`.
void insertBufferBarrierBefore(Instruction &At, Value &Buf) {
  LLVMContext &Ctx = At.getContext();
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {Buf.getType()}, false);
  InlineAsm *IA = InlineAsm::get(FT, "", "r,~{memory}", /*hasSideEffects=*/true);
  IRBuilder<> B(&At);
  CallInst *Bar = B.CreateCall(FT, IA, {&Buf});
  Bar->setDebugLoc(At.getDebugLoc());
}

// --- the version handshake (../schema/wipe-pin.md section 14.7) ------------
//
// A plugin built against one major version of LLVM and loaded into another
// clang can install, run, find nothing and write a record that looks like any
// other. Measured in the lab with a probe plugin that does what this pass
// does first (reads the module, walks its llvm.* declarations): built against
// LLVM 18.1.3 and loaded into clang 19.1.1, its pass ran and read the module's
// llvm.ident correctly ("Ubuntu clang version 19.1.1 (1ubuntu1~24.04.2)"), and
// the host had numbered llvm.memset's declaration 236 where the probe's own
// headers number memset 222 -- so not one MemSetInst matched, the shape of
// this plugin's "nothing to pin" in that host. So the pass checks, before it
// reads or changes anything else:
//
//   1. the producer: every operand of !llvm.ident, the major version after
//      "clang version ", against LLVM_VERSION_MAJOR of the headers this plugin
//      was compiled against;
//   2. the numbering: every llvm.* declaration whose name IntrinsicTable knows,
//      the id the host gave it against the id this build's headers give that
//      name. Not Intrinsic::getBaseName(), which is libLLVM's and so resolves
//      to the host's copy, answering from the host's table (measured: in clang
//      19 the LLVM-18 probe got "llvm.memset" back for 236).
//   3. the host's own table, asked by name: for every entry of IntrinsicTable,
//      the id the host's lookupIntrinsicID gives "llvm.<base>" (libLLVM's, so
//      the host answers) against this build's id. Check 2 only sees what the
//      module declares; IR that declares none of the table's intrinsics (front-
//      end IR under -D_FORTIFY_SOURCE, whose wipe is a call of memset.inline,
//      read back with -x ir) passed checks 1 and 2 in a clang of another
//      version, and the pass then ran there and missed the wipe. This one does
//      not depend on the module.
//
// Any difference is a refusal: no record, nothing changed. A module with no
// llvm.ident, or one that names no clang version, is not refused (the record
// says checked: false and stderr says so); checks 2 and 3 run anyway.
// host.intrinsicsCompared counts check 2's comparisons only.
//
// What this cannot cover: a plugin that fails to load, or crashes or hangs
// before its pass runs, never reaches this code (README, The silent failures).
// And llvm.ident names the compiler that PRODUCED the module, which under
// `-x ir` need not be the host: clang 18 reading IR written by clang 19 is
// refused although the numbering agrees (measured with the probe), the loud
// direction.

struct IntrinsicEntry {
  const char *Base; // the name without "llvm." and without type suffixes
  unsigned Id;      // this build's number for it
};

/// The intrinsics this pass's own matching depends on: MemSetInst (memset,
/// memset.inline), AtomicMemSetInst, MemCpyInst (memcpy, memcpy.inline),
/// isLifetimeStartOrEnd, DbgInfoIntrinsic. Each exists in LLVM 15 to 20.
///
/// A name is matched to the longest entry it extends (tableEntryFor), so every
/// intrinsic whose name is an entry's name plus "." plus more than type
/// suffixes must be an entry itself, or it would be read as the shorter one and
/// refused: in LLVM 15 to 20 those are memset.inline,
/// memset.element.unordered.atomic, memcpy.inline and
/// memcpy.element.unordered.atomic. The last is here for that reason only.
const IntrinsicEntry IntrinsicTable[] = {
    {"memset", Intrinsic::memset},
    {"memset.inline", Intrinsic::memset_inline},
    {"memset.element.unordered.atomic", Intrinsic::memset_element_unordered_atomic},
    {"memcpy", Intrinsic::memcpy},
    {"memcpy.inline", Intrinsic::memcpy_inline},
    {"memcpy.element.unordered.atomic", Intrinsic::memcpy_element_unordered_atomic},
    {"lifetime.start", Intrinsic::lifetime_start},
    {"lifetime.end", Intrinsic::lifetime_end},
    {"dbg.declare", Intrinsic::dbg_declare},
    {"dbg.value", Intrinsic::dbg_value},
    {"dbg.label", Intrinsic::dbg_label},
};

/// The table entry for an llvm.* name: the longest base B such that the name
/// is "llvm.B" or begins with "llvm.B." (so llvm.memset.inline.p0.i64 is
/// memset.inline, not memset). nullptr when no entry fits.
const IntrinsicEntry *tableEntryFor(StringRef Name) {
  const IntrinsicEntry *Best = nullptr;
  size_t BestLen = 0;
  for (const IntrinsicEntry &E : IntrinsicTable) {
    const std::string P = std::string("llvm.") + E.Base;
    const bool Fits = Name == P || (Name.size() > P.size() && hasPrefix(Name, P) &&
                                    Name[P.size()] == '.');
    if (Fits && P.size() > BestLen) {
      Best = &E;
      BestLen = P.size();
    }
  }
  return Best;
}

bool isIdentSpace(char C) {
  return C == ' ' || C == '\t' || C == '\n' || C == '\r' || C == '\f' || C == '\v';
}

/// section 14.7's `ident`: every parenthesised group (nested ones included)
/// and the whitespace directly before it removed, an unmatched ')' removed,
/// surrounding whitespace trimmed. The groups hold build ids, repository URLs
/// and, for a clang built from a local checkout, an absolute path.
std::string stripIdent(StringRef Raw) {
  std::string Out;
  unsigned Depth = 0;
  for (char C : Raw) {
    if (C == '(') {
      if (Depth == 0)
        while (!Out.empty() && isIdentSpace(Out.back())) Out.pop_back();
      ++Depth;
      continue;
    }
    if (C == ')') {
      if (Depth > 0) --Depth;
      continue;
    }
    if (Depth == 0) Out.push_back(C);
  }
  size_t B = 0, E = Out.size();
  while (B < E && isIdentSpace(Out[B])) ++B;
  while (E > B && isIdentSpace(Out[E - 1])) --E;
  return Out.substr(B, E - B);
}

/// The decimal integer directly after "clang version " in `Ident`: the first
/// occurrence that has a digit there, which is what the readers' re-derivation
/// (/clang version ([0-9]+)/) finds. false when there is none.
bool clangMajorOf(const std::string &Ident, int64_t &Major) {
  static const std::string Key = "clang version ";
  for (size_t At = Ident.find(Key); At != std::string::npos;
       At = Ident.find(Key, At + 1)) {
    size_t I = At + Key.size();
    if (I >= Ident.size() || Ident[I] < '0' || Ident[I] > '9') continue;
    int64_t V = 0;
    for (; I < Ident.size() && Ident[I] >= '0' && Ident[I] <= '9'; ++I)
      V = V < 100000000 ? V * 10 + (Ident[I] - '0') : V; // saturates; refused
    Major = V;
    return true;
  }
  return false;
}

/// The record's `host` block, and whether to refuse.
struct HostInfo {
  bool HaveIdent = false;
  std::string Ident;
  bool HaveMajor = false;
  int64_t IdentMajor = 0;
  int64_t IntrinsicsCompared = 0;
  bool Refused = false;
  /// The tail of "WipePin: refusing to install: " when Refused.
  std::string Why;
};

const int64_t BuiltMajor = LLVM_VERSION_MAJOR;

/// The tail of the refusal line for a numbering difference (checks 2 and 3).
std::string tableMismatch(const std::string &HostName, unsigned HostId,
                          const IntrinsicEntry &E) {
  return "intrinsic table mismatch: the host numbers " + HostName + " " +
         std::to_string(HostId) + " and this plugin, built against LLVM " +
         std::to_string(BuiltMajor) + ", numbers llvm." + E.Base + " " +
         std::to_string(E.Id);
}

/// The host's id for an intrinsic name. lookupIntrinsicID is defined in
/// libLLVM, so the copy that runs is the host's and the answer comes from the
/// host's name table. It is a static member of Function up to LLVM 19 and a
/// function in namespace Intrinsic from 20.
unsigned hostIntrinsicId(StringRef Name) {
#if LLVM_VERSION_MAJOR >= 20
  return Intrinsic::lookupIntrinsicID(Name);
#else
  return Function::lookupIntrinsicID(Name);
#endif
}

HostInfo checkHost(const Module &M) {
  HostInfo H;
  if (const NamedMDNode *N = M.getNamedMetadata("llvm.ident")) {
    for (unsigned I = 0, E = N->getNumOperands(); I != E; ++I) {
      const MDNode *Op = N->getOperand(I);
      bool Have = false;
      std::string S;
      if (Op && Op->getNumOperands() > 0)
        if (const auto *MS = dyn_cast_or_null<MDString>(Op->getOperand(0))) {
          S = stripIdent(MS->getString());
          Have = true;
        }
      int64_t Major = 0;
      const bool HaveMajor = Have && clangMajorOf(S, Major);
      if (I == 0) {
        H.HaveIdent = Have;
        H.Ident = S;
        H.HaveMajor = HaveMajor;
        H.IdentMajor = Major;
      }
      // Every operand is compared (a module linked from several units can
      // carry several); the record keeps the first.
      if (HaveMajor && Major != BuiltMajor) {
        H.Refused = true;
        H.Why = "the module was produced by clang " + std::to_string(Major) +
                " (llvm.ident \"" + S + "\") and this plugin was built against LLVM " +
                std::to_string(BuiltMajor);
        return H;
      }
    }
  }
  for (const Function &F : M) {
    if (!F.isDeclaration()) continue;
    const StringRef Name = F.getName();
    if (!hasPrefix(Name, "llvm.")) continue;
    const IntrinsicEntry *E = tableEntryFor(Name);
    if (!E) continue;
    ++H.IntrinsicsCompared;
    const unsigned HostId = F.getIntrinsicID();
    if (HostId != E->Id) {
      H.Refused = true;
      H.Why = tableMismatch(Name.str(), HostId, *E);
      return H;
    }
  }
  for (const IntrinsicEntry &E : IntrinsicTable) {
    const std::string Name = std::string("llvm.") + E.Base;
    const unsigned HostId = hostIntrinsicId(Name);
    if (HostId != E.Id) {
      H.Refused = true;
      H.Why = tableMismatch(Name, HostId, E);
      return H;
    }
  }
  return H;
}

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

// --- the pipeline without pipeline start -------------------------------------
//
// The plugin cannot tell, when it loads, whether it was loaded into a compile or
// into an LTO link: both call the same registration callback, and both carry the
// same WPIN_* environment in a build that exports it. What differs is the
// pipeline each then builds. A compile builds one with a pipeline-start
// extension point, at every level, -flto and -flto=thin compiles included; an
// LTO link's pipeline (lld 18: full LTO and ThinLTO, -O0 to -O3, one backend
// job or several) never has one. Measured with a lab probe plugin at -O0 and
// -O2: in every compile the pipeline-start callback had been invoked before the
// first pass ran, and in every link the first pass (VerifierPass) ran with it
// never invoked; and with this plugin at -O0, -O1, -O2, -O3 and -Os (README).
// clang builds its whole pipeline before it runs any of it, and so does the LTO
// backend.
//
// So: PipelineStartBuilt is set when the pipeline-start callback is invoked --
// at pipeline BUILD time, before any pass runs -- and the first pass this
// process runs with it still unset is the moment to speak. That is a pass
// instrumentation callback rather than a pass on a link-time extension point
// because a ThinLTO link at -O0 invokes no extension point at all (measured:
// none of the six module-level ones), and a pass there could not run.
//
// The same test also speaks in a compile under `-Xclang -disable-llvm-passes`
// that writes IR (`-emit-llvm`): clang builds no optimisation pipeline there,
// but still runs the bitcode writer or IR printer as a pass, and WipePin did not
// run in that process either. That includes the bitcode step of `-save-temps`,
// which clang runs with -disable-llvm-passes; its next step builds the whole
// pipeline from the .bc, and WipePin runs and writes the record there
// (measured). Not covered: a process that runs no pass through the
// instrumentation at all (`-disable-llvm-passes` with `-c` or `-S`, where code
// generation is not a new-pass-manager pipeline), and a host whose PassBuilder
// has no instrumentation callbacks (clang 18 and lld 18 both have them).

/// Set when the pipeline-start callback is invoked, i.e. when a pipeline that
/// will run WipePinPass is built.
std::atomic<bool> PipelineStartBuilt{false};
/// Set when the load-time callback removed a file at WPIN_OUT, in any of this
/// process's loads (a multi-module ThinLTO link registers once per backend).
std::atomic<bool> RemovedAtLoad{false};
/// The line is printed once per process, however many modules or backend
/// threads reach the callback.
std::atomic<bool> NoPipelineStartSaid{false};

/// The line, exactly. check-fixture-loop.py and the LTO probe
/// (compiler/eval/repair-loop/tools/lib/lto.mjs) match it character for character.
std::string noPipelineStartLine(bool Removed) {
  return std::string("WipePin: loaded into a pipeline built without the "
                     "pipeline-start extension point (an LTO link, or a compile "
                     "under -disable-llvm-passes), where this pass does not "
                     "run; nothing was pinned in this process, and ") +
         (Removed ? "the file at WPIN_OUT was removed when the plugin loaded"
                  : "there was no file at WPIN_OUT when the plugin loaded") +
         "\n";
}

void sayIfNoPipelineStart() {
  if (PipelineStartBuilt.load()) return;
  if (NoPipelineStartSaid.exchange(true)) return;
  // One write of the whole line: ThinLTO backends run on several threads.
  errs() << noPipelineStartLine(RemovedAtLoad.load());
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

    // --- the version handshake, before anything else is read ----------------
    const HostInfo H = checkHost(M);
    if (H.Refused) {
      // WPIN_OUT was cleared when the plugin loaded, so "no record" is the
      // truth about this compile; pin.sh turns it into exit 3.
      errs() << "WipePin: refusing to install: " << H.Why << "\n";
      return PreservedAnalyses::all();
    }
    if (!H.HaveMajor)
      errs() << "WipePin: the module's llvm.ident names no clang version ("
             << (H.HaveIdent ? "\"" + H.Ident + "\"" : std::string("absent"))
             << "); the host compiler was not checked against LLVM " << BuiltMajor
             << "\n";

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
    std::vector<BarrierSite> BarrierSites;
    std::vector<CallInst *> ToBarrier;
    std::vector<ZeroCopySite> ZeroCopySites;
    std::vector<MemCpyInst *> ToZeroCopyIntrinsic;  // -> volatile memset
    std::vector<CallInst *> ToZeroCopyCall;         // -> barrier after
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
          // A copy from an all-zero constant global. Repaired with
          // WPIN_ZERO_COPY=1, counted otherwise. A volatile copy is already
          // kept, and is neither counted nor listed.
          if (auto *MC = dyn_cast<MemCpyInst>(&I)) {
            const GlobalVariable *GV = zeroConstantSource(MC->getRawSource());
            if (!GV || MC->isVolatile()) continue;
            if (!C.ZeroCopy) {
              U.ZeroGlobalCopy++;
              continue;
            }
            ZeroCopySites.push_back(zeroCopySite(*F, "intrinsic", "llvm.memcpy",
                                                 *GV, MC->getRawDest(),
                                                 MC->getLength(),
                                                 MC->getDebugLoc()));
            ToZeroCopyIntrinsic.push_back(MC);
            continue;
          }
          // Wipes this pass does not touch, counted so that "nothing was
          // pinned" can be told apart from "there was nothing to pin".
          if (auto *CB = dyn_cast<CallBase>(&I)) {
            const Function *Callee = CB->getCalledFunction();
            if (!Callee || Callee->isIntrinsic()) continue;
            const StringRef Name = Callee->getName();
            const bool IsLib = Name == "memset";
            const bool IsChk = Name == "__memset_chk";
            const bool IsWrap = hasPrefix(Name, "memset.");
            const bool IsBz = Name == "bzero";
            const bool IsBzWrap = hasPrefix(Name, "bzero.");
            // memcpy as a call -- the -D_FORTIFY_SOURCE wrapper memcpy.inline,
            // __memcpy_chk, or a libcall -- from an all-zero constant global.
            // The call stays (and with it the fortify check); the barrier
            // after it keeps the bytes it wrote. A call or an invoke counts;
            // only a plain call is repaired, and an invoke stays counted with
            // the switch on (section 14.3).
            if (Name == "memcpy" || Name == "__memcpy_chk" ||
                hasPrefix(Name, "memcpy.")) {
              const GlobalVariable *GV =
                  CB->arg_size() >= 3 ? zeroConstantSource(CB->getArgOperand(1))
                                      : nullptr;
              if (!GV) continue;
              auto *CpyCall = dyn_cast<CallInst>(CB);
              if (!C.ZeroCopy || !CpyCall) {
                U.ZeroGlobalCopyCall++;
                continue;
              }
              ZeroCopySites.push_back(zeroCopySite(
                  *F, "call", Name, *GV, CpyCall->getArgOperand(0),
                  CpyCall->getArgOperand(2), CpyCall->getDebugLoc()));
              ToZeroCopyCall.push_back(CpyCall);
              continue;
            }
            if (!IsLib && !IsChk && !IsWrap && !IsBz && !IsBzWrap) continue;
            // WPIN_BARRIER_CALLS: a plain call (not an invoke) whose fill
            // argument is the constant zero is repaired, and so is no longer
            // "left alone"; anything else is counted exactly as before.
            auto *Call = dyn_cast<CallInst>(CB);
            // bzero(dest, len) has no fill argument (it is always zero), and
            // its length is argument 1.
            const bool IsBzAny = IsBz || IsBzWrap;
            const bool ZeroFillCall = Call && (IsBzAny ? Call->arg_size() >= 2
                                                      : (Call->arg_size() >= 3 && isZeroValue(Call->getArgOperand(1))));
            if (C.BarrierCalls && ZeroFillCall) {
              BarrierSite B;
              B.Function = F->getName().str();
              B.Callee = Name.str();
              if (const auto *Len = dyn_cast<ConstantInt>(Call->getArgOperand(IsBzAny ? 1 : 2))) {
                if (Len->getValue().getActiveBits() <= 63) {
                  B.HaveLength = true;
                  B.LengthBytes = static_cast<int64_t>(Len->getZExtValue());
                }
              }
              if (const DebugLoc &DL = Call->getDebugLoc()) {
                B.HaveLine = true;
                B.Line = static_cast<int64_t>(DL.getLine());
              }
              BarrierSites.push_back(std::move(B));
              ToBarrier.push_back(Call);
              continue;
            }
            if (IsLib) U.LibcallMemset++;
            else if (IsChk) U.MemsetChk++;
            else if (IsWrap) U.InlineWrapperMemset++;
            else if (IsBz) U.BzeroCall++;
            else U.InlineWrapperBzero++;
          }
        }
      }
    }

    // --- the buffer census (WPIN_BUFFER_BARRIER) -----------------------------
    // Read on the same unmodified IR as the census above: nothing is changed
    // until every site of every function in scope has been read. With the
    // switch off nothing here runs, and the record says enabled: false.
    std::vector<BufferSite> BufSites;
    std::vector<std::pair<Instruction *, AllocaInst *>> ToBufferBarrier;
    int64_t BufNotStack = 0;
    // Buffers left without a barrier, counted on stderr (section 14.6 fixes
    // the record's keys): every zero fill followed by a later use in the same
    // lifetime, or no lifetime end and no return the buffer dominates.
    int64_t BufInitialiserOnly = 0;
    int64_t BufNoPlace = 0;
    if (C.BufferBarrier) {
      const DataLayout &DLay = M.getDataLayout();
      for (Function *F : InScope) {
        const DominatorTree DT(*F);
        const LoopInfo LI(DT);
        const CleanupDispatch CD(*F);
        // Every zero fill of a stack buffer, in instruction order.
        struct Fill {
          const Instruction *I;
          FillReason R;
        };
        std::vector<AllocaInst *> Order;
        DenseMap<const AllocaInst *, std::vector<Fill>> Fills;
        auto Note = [&](const Value *Dest, const Instruction &I, FillReason R,
                        bool AggregateOnly) {
          const AllocaInst *AI = bufferAllocaOf(Dest);
          if (!AI) {
            BufNotStack++;
            return;
          }
          if (AggregateOnly && !isAggregateBuffer(*AI)) return;
          std::vector<Fill> &V = Fills[AI];
          if (V.empty()) Order.push_back(const_cast<AllocaInst *>(AI));
          V.push_back({&I, R});
        };
        for (BasicBlock &BB : *F) {
          for (Instruction &I : BB) {
            if (auto *MS = dyn_cast<MemSetInst>(&I)) {
              if (isZeroFill(*MS)) Note(MS->getDest(), I, FillReason::Memset, false);
              continue;
            }
            if (auto *MC = dyn_cast<MemCpyInst>(&I)) {
              if (zeroConstantSource(MC->getRawSource()))
                Note(MC->getRawDest(), I, FillReason::ZeroCopy, false);
              continue;
            }
            if (auto *SI = dyn_cast<StoreInst>(&I)) {
              // A volatile store is kept already and needs no reader.
              if (!SI->isVolatile() && isZeroConstant(SI->getValueOperand()) &&
                  LI.getLoopFor(&BB))
                Note(SI->getPointerOperand(), I, FillReason::LoopStore, true);
              continue;
            }
            auto *Call = dyn_cast<CallInst>(&I);
            if (!Call) continue;
            const Function *Callee = Call->getCalledFunction();
            if (!Callee || Callee->isIntrinsic()) continue;
            const StringRef Name = Callee->getName();
            if (Name == "bzero" || hasPrefix(Name, "bzero.")) {
              if (Call->arg_size() >= 2)
                Note(Call->getArgOperand(0), I, FillReason::Memset, false);
            } else if (Name == "memset" || Name == "__memset_chk" ||
                       hasPrefix(Name, "memset.")) {
              if (Call->arg_size() >= 3 && isZeroValue(Call->getArgOperand(1)))
                Note(Call->getArgOperand(0), I, FillReason::Memset, false);
            } else if (Name == "memcpy" || Name == "__memcpy_chk" ||
                       hasPrefix(Name, "memcpy.")) {
              if (Call->arg_size() >= 3 && zeroConstantSource(Call->getArgOperand(1)))
                Note(Call->getArgOperand(0), I, FillReason::ZeroCopy, false);
            }
          }
        }
        for (AllocaInst *AI : Order) {
          const std::vector<Fill> &V = Fills[AI];
          // The fill `reason` names: the first one no later use follows in
          // the same lifetime (a wipe). When every fill has a later use (an
          // initialiser only), the buffer gets no barrier: its last stores are
          // the secret itself, and a barrier would keep them in memory to the
          // end of the lifetime with no wipe to protect. Sites, in order:
          // buffers by their first zero fill, then each buffer's anchors in
          // instruction order (section 14.6).
          const Fill *Rep = nullptr;
          std::vector<const Instruction *> Wipes;
          for (const Fill &Fl : V)
            if (bufferLaterUse(*Fl.I, *AI, DT, LI, CD) != LaterUse::Yes) {
              if (!Rep) Rep = &Fl;
              Wipes.push_back(Fl.I);
            }
          if (!Rep) {
            BufInitialiserOnly++;
            continue;
          }
          // The places, in instruction order: every point where a wipe's path
          // leaves the buffer's lifetime, found by walking from each wipe
          // (useWithinLifetime). Such a point is a reachable lifetime end of
          // the buffer, or a reachable `ret` -- before the musttail call it
          // follows, which must stay directly before its `ret`. Nothing else is
          // a place: not a lifetime end only paths without a wipe reach, where
          // a barrier protects no wipe and keeps the buffer's last stores, the
          // secret, in memory; and not a lifetime end in a block no path
          // reaches -- clang puts the scope's lifetime end after a musttail
          // call and its `ret`, where a barrier would be deleted with the dead
          // block while the record still counted it. If a wipe reaches a `ret`
          // the alloca does not dominate, or a block that ends in `unreachable`
          // (after a call that does not return, such as exit or abort), that
          // path cannot be covered, and the buffer gets no barrier at all:
          // barriers on the other paths only would let the record and pin.sh
          // say "repaired" for a wipe this path still loses. stderr counts it.
          auto Reaches = [&](const Instruction *At) {
            SmallPtrSet<const Instruction *, 2> Target;
            Target.insert(At);
            for (const Instruction *Wi : Wipes)
              if (useWithinLifetime(*Wi, *AI, Target)) return true;
            return false;
          };
          SmallPtrSet<const Instruction *, 8> ReachedExits;
          bool Uncovered = false;
          for (BasicBlock &BB : *F) {
            if (!DT.isReachableFromEntry(&BB)) continue;
            Instruction *Term = BB.getTerminator();
            if (isa_and_nonnull<UnreachableInst>(Term)) {
              if (Reaches(Term)) {
                Uncovered = true;
                break;
              }
              continue;
            }
            auto *Ret = dyn_cast_or_null<ReturnInst>(Term);
            if (!Ret) continue;
            Instruction *At = Ret;
            if (CallInst *MustTail = BB.getTerminatingMustTailCall()) At = MustTail;
            if (!Reaches(At)) continue;
            if (!DT.dominates(AI, At)) {
              Uncovered = true;
              break;
            }
            ReachedExits.insert(At);
          }
          std::vector<std::pair<Instruction *, const char *>> Places;
          if (!Uncovered)
            for (Instruction &I : instructions(*F)) {
              if (ReachedExits.count(&I)) {
                Places.emplace_back(&I, "ret");
                continue;
              }
              if (auto *II = dyn_cast<IntrinsicInst>(&I))
                if (II->getIntrinsicID() == Intrinsic::lifetime_end &&
                    getUnderlyingObject(II->getArgOperand(II->arg_size() - 1)) == AI &&
                    DT.isReachableFromEntry(I.getParent()) && Reaches(&I))
                  Places.emplace_back(&I, "lifetime-end");
            }
          if (Places.empty()) {
            BufNoPlace++;
            continue;
          }
          BufferSite S;
          S.Function = F->getName().str();
          S.HaveBuffer = bufferNameOf(*AI, S.Buffer);
          // In bits: AllocaInst::getAllocationSize first appears in LLVM 16.
          auto Bits = AI->getAllocationSizeInBits(DLay);
          if (Bits && !Bits->isScalable()) {
            S.HaveBytes = true;
            S.Bytes = static_cast<int64_t>(Bits->getFixedValue() / 8);
          }
          S.Reason = Rep->R;
          for (auto &Pl : Places) {
            S.Anchor = Pl.second;
            BufSites.push_back(S);
            ToBufferBarrier.emplace_back(Pl.first, AI);
          }
        }
      }
    }

    // --- the pin -------------------------------------------------------------
    int64_t Barriered = 0;
    if (!C.DryRun) {
      for (MemSetInst *MS : ToPin) {
        MS->setVolatile(ConstantInt::getTrue(Ctx));
        Pinned++;
      }
      for (CallInst *Call : ToBarrier) {
        insertBarrierAfter(*Call);
        Barriered++;
      }
    }
    int64_t ZeroCopied = 0;
    if (!C.DryRun) {
      for (MemCpyInst *MC : ToZeroCopyIntrinsic) {
        replaceWithVolatileMemset(*MC);
        ZeroCopied++;
      }
      for (CallInst *Call : ToZeroCopyCall) {
        insertBarrierAfter(*Call);
        ZeroCopied++;
      }
    }
    int64_t BufBarriered = 0;
    if (!C.DryRun) {
      for (auto &P : ToBufferBarrier) {
        insertBufferBarrierBefore(*P.first, *P.second);
        BufBarriered++;
      }
    }

    const std::string UnhandledText =
        "libcallMemset=" + std::to_string(U.LibcallMemset) +
        " memsetChk=" + std::to_string(U.MemsetChk) +
        " nonZeroFill=" + std::to_string(U.NonZeroFill) +
        " atomicMemset=" + std::to_string(U.AtomicMemset) +
        " inlineWrapperMemset=" + std::to_string(U.InlineWrapperMemset) +
        " bzeroCall=" + std::to_string(U.BzeroCall) +
        " inlineWrapperBzero=" + std::to_string(U.InlineWrapperBzero) +
        " zeroGlobalCopy=" + std::to_string(U.ZeroGlobalCopy) +
        " zeroGlobalCopyCall=" + std::to_string(U.ZeroGlobalCopyCall);
    const bool AnyUnhandled = U.LibcallMemset > 0 || U.MemsetChk > 0 ||
                              U.NonZeroFill > 0 || U.AtomicMemset > 0 ||
                              U.InlineWrapperMemset > 0 || U.BzeroCall > 0 ||
                              U.InlineWrapperBzero > 0 ||
                              U.ZeroGlobalCopy > 0 || U.ZeroGlobalCopyCall > 0;
    int64_t FollowedByUse = 0;
    for (const Site &S : Sites)
      if (S.FollowedByUse == LaterUse::Yes) FollowedByUse++;

    if (C.DryRun && WouldPin > 0)
      errs() << "WipePin: dry run: " << WouldPin
             << " zero-fill llvm.memset site(s) would be pinned; none was "
                "changed\n";
    if (C.DryRun && !ToBarrier.empty())
      errs() << "WipePin: dry run: " << ToBarrier.size()
             << " zero-fill memset or bzero call(s) would get a barrier; none "
                "was changed\n";
    if (C.DryRun && !ZeroCopySites.empty())
      errs() << "WipePin: dry run: " << ZeroCopySites.size()
             << " copy(ies) from an all-zero constant would be repaired; none "
                "was changed\n";
    if (C.DryRun && !BufSites.empty())
      errs() << "WipePin: dry run: " << BufSites.size()
             << " buffer barrier(s) would be placed; none was changed\n";
    // A zero fill the buffer barrier cannot cover: its destination is not a
    // stack buffer of the function, so there is no lifetime end here to stand
    // at. Counted on stderr; section 14.6 fixes the record's keys.
    if (C.BufferBarrier && BufNotStack > 0)
      errs() << "WipePin: buffer barrier: " << BufNotStack
             << " zero fill(s) in scope write memory that is not a stack "
                "buffer of the function (an argument, a global, the heap, or a "
                "pointer this pass does not follow); no barrier covers them\n";
    // Buffers the census left without a barrier. An initialiser-like buffer
    // is the buffer-barrier twin of the followedByUse count in the partial
    // line below. The later use is read on the IR before any optimisation, so
    // a wipe followed by code that touches the buffer -- even code the
    // optimiser then removes -- is counted here too, and the line does not
    // call it "not a wipe". A buffer with no place is one where a return its
    // wipe reaches is not dominated by the alloca (an alloca or
    // variable-length array inside a branch or a loop), or that has neither a
    // reachable lifetime end nor a return its wipe reaches (a function that
    // does not return).
    if (C.BufferBarrier && BufInitialiserOnly > 0)
      errs() << "WipePin: buffer barrier: " << BufInitialiserOnly
             << " buffer(s) not barriered: every zero fill is followed by a "
                "later use (read as an initialiser; a wipe that later code "
                "still touches, even code the optimiser removes, is counted "
                "here too)\n";
    if (C.BufferBarrier && BufNoPlace > 0)
      errs() << "WipePin: buffer barrier: " << BufNoPlace
             << " buffer(s) not barriered: the buffer does not dominate a "
                "return its wipe reaches, or there is no place (an alloca or "
                "variable-length array inside a branch or loop, or a function "
                "that does not return)\n";
    if (WouldPin == 0 && ZeroFillInScope == 0 && BarrierSites.empty() &&
        ZeroCopySites.empty() && BufSites.empty())
      errs() << "WipePin: nothing to pin in scope in " << ModuleName
             << " (zero-fill llvm.memset in scope: 0; unhandled in scope: "
             << UnhandledText << ")\n";
    // The partial repair. Either a recorded site is followed by a later use of
    // its buffer -- so it is an initialiser or a clear-before-fill, and pinning
    // it says nothing about the wipe -- or something was pinned while a
    // memset-shaped call in the same scope was left alone. In both cases the
    // record's pinnedCount is positive and the compile looks repaired; this
    // line is what keeps a build log from agreeing.
    if (FollowedByUse > 0 ||
        ((Pinned > 0 || Barriered > 0 || ZeroCopied > 0 || BufBarriered > 0) &&
         AnyUnhandled))
      errs() << "WipePin: partial: pinned " << Pinned << " site(s) in "
             << ModuleName << "; " << FollowedByUse
             << " followed by a later use of the same buffer (initialiser-like, "
                "not a wipe); unhandled in scope: "
             << UnhandledText << "\n";

    emit(ModuleName, RequestedJ, ResolutionJ, Sites, Pinned, WouldPin,
         ZeroFillInScope, ZeroFillInModule, U, BarrierSites, Barriered,
         ZeroCopySites, ZeroCopied, BufSites, BufBarriered, H);

    return (Pinned > 0 || Barriered > 0 || ZeroCopied > 0 || BufBarriered > 0)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
  }

private:
  void emit(const std::string &ModuleName, Json RequestedJ, Json ResolutionJ,
            const std::vector<Site> &Sites, int64_t Pinned, int64_t WouldPin,
            int64_t ZeroFillInScope, int64_t ZeroFillInModule,
            const Unhandled &U, const std::vector<BarrierSite> &BarrierSites,
            int64_t Barriered, const std::vector<ZeroCopySite> &ZeroCopySites,
            int64_t ZeroCopied, const std::vector<BufferSite> &BufSites,
            int64_t BufBarriered, const HostInfo &H) const {
    const Config &C = *Cfg;
    Json R = Json::object();
    R.set("schemaVersion", Json::str("wipe-pin-v3"));
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
                                Json::integer(U.InlineWrapperMemset))
                           .set("bzeroCall", Json::integer(U.BzeroCall))
                           .set("inlineWrapperBzero", Json::integer(U.InlineWrapperBzero))
                           .set("zeroGlobalCopy", Json::integer(U.ZeroGlobalCopy))
                           .set("zeroGlobalCopyCall", Json::integer(U.ZeroGlobalCopyCall)));

    // wipe-pin-v3: the four blocks are written on every record, whatever the
    // configuration; a switch that is off reads enabled: false, no sites, and
    // every count 0 (../schema/wipe-pin.md section 14.4 to 14.7).
    Json BS = Json::array();
    for (const BarrierSite &S : BarrierSites)
      BS.push(Json::object()
                  .set("function", Json::str(S.Function))
                  .set("callee", Json::str(S.Callee))
                  .set("lengthBytes",
                       S.HaveLength ? Json::integer(S.LengthBytes) : Json::null())
                  .set("line", S.HaveLine ? Json::integer(S.Line) : Json::null()));
    R.set("barrierCalls",
          Json::object()
              .set("enabled", Json::boolean(C.BarrierCalls))
              .set("sites", std::move(BS))
              .set("barrierCount", Json::integer(Barriered))
              .set("wouldBarrierCount",
                   Json::integer(static_cast<int64_t>(BarrierSites.size()))));
    Json ZS = Json::array();
    for (const ZeroCopySite &S : ZeroCopySites)
      ZS.push(Json::object()
                  .set("function", Json::str(S.Function))
                  .set("form", Json::str(S.Form))
                  .set("callee", Json::str(S.Callee))
                  .set("source", Json::str(S.Source))
                  .set("destKind", Json::str(S.DestKind))
                  .set("lengthBytes",
                       S.HaveLength ? Json::integer(S.LengthBytes) : Json::null())
                  .set("line", S.HaveLine ? Json::integer(S.Line) : Json::null()));
    R.set("zeroCopy",
          Json::object()
              .set("enabled", Json::boolean(C.ZeroCopy))
              .set("sites", std::move(ZS))
              .set("repairedCount", Json::integer(ZeroCopied))
              .set("wouldRepairCount",
                   Json::integer(static_cast<int64_t>(ZeroCopySites.size()))));
    // Section 14.6. `count` is the barriers placed (0 in a dry run); `sites`
    // has one entry per barrier placed, or that would have been placed in a
    // dry run. With the switch off the census put nothing in BufSites, and the
    // block is {"enabled":false,"count":0,"sites":[]}.
    Json FS = Json::array();
    for (const BufferSite &S : BufSites)
      FS.push(Json::object()
                  .set("function", Json::str(S.Function))
                  .set("buffer", S.HaveBuffer ? Json::str(S.Buffer) : Json::null())
                  .set("bytes", S.HaveBytes ? Json::integer(S.Bytes) : Json::null())
                  .set("reason", Json::str(fillReasonName(S.Reason)))
                  .set("anchor", Json::str(S.Anchor)));
    R.set("bufferBarriers", Json::object()
                                .set("enabled", Json::boolean(C.BufferBarrier))
                                .set("count", Json::integer(BufBarriered))
                                .set("sites", std::move(FS)));
    R.set("host",
          Json::object()
              .set("ident", H.HaveIdent ? Json::str(H.Ident) : Json::null())
              .set("identMajor", H.HaveMajor ? Json::integer(H.IdentMajor) : Json::null())
              .set("builtMajor", Json::integer(BuiltMajor))
              .set("checked", Json::boolean(H.HaveMajor))
              .set("intrinsicsCompared", Json::integer(H.IntrinsicsCompared)));

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
             << "); the IR was "
             << (Pinned + Barriered + ZeroCopied + BufBarriered > 0 ? "changed"
                                                                     : "not changed")
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
            //
            // It also runs when an LTO link loads the plugin, and there the
            // file it removes may be the record the compile step wrote. That
            // is kept, on purpose: whether this is a link is only known once a
            // pipeline has been built, and a compile that builds none
            // (-disable-llvm-passes) would then keep a stale record. Instead
            // the link says what happened (sayIfNoPipelineStart).
            std::string Why;
            bool Removed = false;
            if (!wpin::clearStaleRecord(Why, Removed)) {
              errs() << "WipePin: refusing to install: " << Why << "\n";
              return;
            }
            if (Removed) wpin::RemovedAtLoad.store(true);
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
                  wpin::PipelineStartBuilt.store(true);
                  MPM.addPass(wpin::WipePinPass(Shared, L));
                });
            // Read-only: the callback gets the pass's name and IR unit and
            // looks at neither.
            if (PassInstrumentationCallbacks *PIC =
                    PB.getPassInstrumentationCallbacks())
              PIC->registerBeforeNonSkippedPassCallback(
                  [](StringRef, Any) { wpin::sayIfNoPipelineStart(); });
          }};
}
