#include "Extractors.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"

#include <algorithm>

using namespace llvm;

namespace irck {

const char *extractorName(Extractor E) {
  switch (E) {
  case Extractor::WipeEffect: return "ir.wipe-effect";
  case Extractor::GuardedCall: return "ir.guarded-call";
  case Extractor::ForbiddenCallee: return "ir.forbidden-callee";
  }
  return "ir.unknown";
}

bool parseExtractor(const std::string &S, Extractor &Out) {
  if (S == "ir.wipe-effect") { Out = Extractor::WipeEffect; return true; }
  if (S == "ir.guarded-call") { Out = Extractor::GuardedCall; return true; }
  if (S == "ir.forbidden-callee") { Out = Extractor::ForbiddenCallee; return true; }
  return false;
}

const char *targetKindName(TargetKind K) {
  switch (K) {
  case TargetKind::Alloca: return "alloca";
  case TargetKind::Argument: return "argument";
  case TargetKind::Global: return "global";
  case TargetKind::Other: return "other";
  }
  return "other";
}

int64_t UnitFacts::effect(Extractor E) const {
  switch (E) {
  case Extractor::WipeEffect:
    return EffectCallSites + ZeroStores;
  case Extractor::GuardedCall:
    // A guard whose branch has folded to a constant is not guarding anything,
    // so its call site stops counting even though the instruction is still
    // sitting in the block waiting for the next sweep.
    return LiveCondBranches > 0 ? EffectCallSites : 0;
  case Extractor::ForbiddenCallee:
    return ForbiddenCallSites;
  }
  return 0;
}

Json UnitFacts::toJson(Extractor E) const {
  Json J = Json::object();
  J.set("unitPresent", Json::boolean(UnitPresent));
  J.set("effect", Json::integer(effect(E)));
  J.set("effectCallSites", Json::integer(EffectCallSites));
  J.set("zeroStores", Json::integer(ZeroStores));
  J.set("forbiddenCallSites", Json::integer(ForbiddenCallSites));
  J.set("liveConditionalBranches", Json::integer(LiveCondBranches));
  J.set("allocaCount", Json::integer(AllocaCount));
  J.set("allocaSizesBytes", intArray(AllocaSizes));
  J.set("allocasEscapingToOpaqueCall", Json::integer(AllocasEscapingToOpaqueCall));
  Json T = Json::array();
  for (const EffectTarget &Tg : Targets) {
    Json E1 = Json::object();
    E1.set("kind", Json::str(targetKindName(Tg.Kind)));
    E1.set("sizeBytes", Json::integer(Tg.SizeBytes));
    E1.set("viaCallSite", Json::boolean(Tg.ViaCallSite));
    T.push(std::move(E1));
  }
  J.set("effectTargets", std::move(T));
  return J;
}

/// Exact match, or the intrinsic form: llvm.memset -> llvm.memset.p0.i64.
static bool matchesSymbol(StringRef Name, const std::vector<std::string> &Syms) {
  for (const std::string &S : Syms) {
    if (Name == S) return true;
    if (Name.starts_with(S) && Name.size() > S.size() && Name[S.size()] == '.')
      return true;
  }
  return false;
}

/// Intrinsics that do not stop SROA from promoting the object they address.
/// The list matters: `llvm.memset` on an alloca is *splittable*, so its
/// presence is not evidence that the buffer has to stay in memory, while a call
/// to an ordinary function is.
static bool intrinsicIsTransparentToPromotion(Intrinsic::ID ID) {
  switch (ID) {
  case Intrinsic::lifetime_start:
  case Intrinsic::lifetime_end:
  case Intrinsic::invariant_start:
  case Intrinsic::invariant_end:
  case Intrinsic::assume:
  case Intrinsic::memset:
  case Intrinsic::memset_inline:
  case Intrinsic::memcpy:
  case Intrinsic::memcpy_inline:
  case Intrinsic::memmove:
    return true;
  default:
    return ID == Intrinsic::not_intrinsic ? false : false;
  }
}

/// Does this alloca's address reach something that stops it being promoted out
/// of memory?
///
/// This is not a capture analysis and is not trying to be one. It answers the
/// narrower question the LOST/NOT_APPLICABLE decision actually needs: could a
/// promotion pass have removed this object. A `nocapture` pointer argument to
/// an out-of-line callee still pins the object in memory, so `nocapture` is
/// deliberately not consulted.
static bool allocaEscapesToOpaqueCall(const AllocaInst *AI) {
  SmallVector<const Value *, 16> Work;
  SmallPtrSet<const Value *, 16> Seen;
  Work.push_back(AI);
  Seen.insert(AI);

  while (!Work.empty()) {
    const Value *V = Work.pop_back_val();
    for (const User *U : V->users()) {
      if (const auto *CB = dyn_cast<CallBase>(U)) {
        // Only an operand position counts; being the callee of an indirect call
        // is handled by the same branch and is also an escape.
        const Function *Callee = CB->getCalledFunction();
        if (Callee && Callee->isIntrinsic() &&
            intrinsicIsTransparentToPromotion(Callee->getIntrinsicID()))
          continue;
        if (isa<DbgInfoIntrinsic>(CB)) continue;
        return true;
      }
      if (const auto *SI = dyn_cast<StoreInst>(U)) {
        // Storing *through* the pointer is fine; storing the pointer itself
        // hands the address to whoever reads that slot.
        if (SI->getValueOperand() == V) return true;
        continue;
      }
      if (isa<LoadInst>(U)) continue;
      if (isa<ReturnInst>(U)) return true;
      if (isa<PtrToIntInst>(U)) return true;
      if (isa<GetElementPtrInst>(U) || isa<BitCastInst>(U) ||
          isa<AddrSpaceCastInst>(U) || isa<PHINode>(U) || isa<SelectInst>(U)) {
        if (Seen.insert(U).second) Work.push_back(U);
        continue;
      }
      if (isa<ICmpInst>(U)) continue;
      // Anything unrecognised is treated as an escape: erring towards "the
      // object is still pinned" turns an unknown into LOST rather than into
      // NOT_APPLICABLE, and a false LOST is visible while a false
      // NOT_APPLICABLE is silence.
      return true;
    }
  }
  return false;
}

static EffectTarget classifyTarget(const Value *Ptr, const DataLayout &DL,
                                   bool ViaCallSite) {
  EffectTarget T;
  T.ViaCallSite = ViaCallSite;
  const Value *UO = getUnderlyingObject(Ptr);
  if (const auto *AI = dyn_cast<AllocaInst>(UO)) {
    T.Kind = TargetKind::Alloca;
    T.Name = AI->getName().str();
    if (auto Sz = AI->getAllocationSize(DL))
      if (!Sz->isScalable()) T.SizeBytes = static_cast<int64_t>(Sz->getFixedValue());
    return T;
  }
  if (isa<Argument>(UO)) { T.Kind = TargetKind::Argument; return T; }
  if (isa<GlobalValue>(UO)) { T.Kind = TargetKind::Global; return T; }
  T.Kind = TargetKind::Other;
  return T;
}

UnitFacts collectFacts(const Function &F, const ExtractorConfig &C) {
  UnitFacts U;
  U.UnitPresent = !F.isDeclaration();
  if (!U.UnitPresent) return U;

  const DataLayout &DL = F.getParent()->getDataLayout();

  for (const BasicBlock &BB : F) {
    if (const auto *BI = dyn_cast_or_null<BranchInst>(BB.getTerminator()))
      if (BI->isConditional() && !isa<Constant>(BI->getCondition()))
        U.LiveCondBranches++;

    for (const Instruction &I : BB) {
      if (const auto *AI = dyn_cast<AllocaInst>(&I)) {
        U.AllocaCount++;
        int64_t Bytes = -1;
        if (auto Sz = AI->getAllocationSize(DL))
          if (!Sz->isScalable()) {
            Bytes = static_cast<int64_t>(Sz->getFixedValue());
            U.AllocaSizes.push_back(Bytes);
          }
        U.AllocaObjects.emplace_back(AI->getName().str(), Bytes);
        if (allocaEscapesToOpaqueCall(AI)) U.AllocasEscapingToOpaqueCall++;
        continue;
      }

      if (const auto *CB = dyn_cast<CallBase>(&I)) {
        // interfaces.md section 4: resolve the callee of the call instruction.
        // An unresolved (indirect) callee is not counted -- and that is
        // recorded rather than assumed away, because it is a real hole in this
        // oracle and is listed as a degradation risk in properties.json.
        const Function *Callee = CB->getCalledFunction();
        if (!Callee) continue;
        StringRef Name = Callee->getName();
        if (matchesSymbol(Name, C.EffectSymbols)) {
          U.EffectCallSites++;
          if (CB->arg_size() >= 1 && CB->getArgOperand(0)->getType()->isPointerTy())
            U.Targets.push_back(classifyTarget(CB->getArgOperand(0), DL, true));
          else
            U.Targets.push_back(EffectTarget{TargetKind::Other, -1, true, std::string()});
        }
        if (matchesSymbol(Name, C.ForbiddenSymbols)) U.ForbiddenCallSites++;
        continue;
      }

      if (const auto *SI = dyn_cast<StoreInst>(&I)) {
        const auto *CV = dyn_cast<Constant>(SI->getValueOperand());
        if (!CV || !CV->isNullValue()) continue;
        const Value *UO = getUnderlyingObject(SI->getPointerOperand());
        if (isa<AllocaInst>(UO) || isa<Argument>(UO)) {
          U.ZeroStores++;
          U.Targets.push_back(classifyTarget(SI->getPointerOperand(), DL, false));
        }
        continue;
      }
    }
  }

  std::sort(U.AllocaSizes.begin(), U.AllocaSizes.end());
  return U;
}

bool naiveModuleSymbolPresent(const Module &M,
                              const std::vector<std::string> &Symbols) {
  for (const Function &F : M)
    if (matchesSymbol(F.getName(), Symbols)) return true;
  return false;
}

std::vector<std::string>
declaredButUncalledSymbols(const Module &M,
                           const std::vector<std::string> &Symbols) {
  std::vector<std::string> Out;
  for (const Function &Cand : M) {
    if (!matchesSymbol(Cand.getName(), Symbols)) continue;
    unsigned Calls = 0;
    for (const Function &F : M) {
      if (F.isDeclaration()) continue;
      for (const BasicBlock &BB : F)
        for (const Instruction &I : BB)
          if (const auto *CB = dyn_cast<CallBase>(&I))
            if (CB->getCalledFunction() == &Cand) Calls++;
    }
    if (Calls == 0) Out.push_back(Cand.getName().str());
  }
  std::sort(Out.begin(), Out.end());
  return Out;
}

int64_t moduleWideCallSites(const Module &M,
                            const std::vector<std::string> &Symbols) {
  int64_t N = 0;
  for (const Function &F : M) {
    if (F.isDeclaration()) continue;
    for (const BasicBlock &BB : F)
      for (const Instruction &I : BB)
        if (const auto *CB = dyn_cast<CallBase>(&I))
          if (const Function *Callee = CB->getCalledFunction())
            if (matchesSymbol(Callee->getName(), Symbols)) N++;
  }
  return N;
}

} // namespace irck
