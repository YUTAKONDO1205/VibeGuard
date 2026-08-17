#include "MetadataChannel.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

#include <algorithm>

using namespace llvm;

namespace irck {

namespace {

/// The annotation string a global holds, or empty when the operand is not the
/// shape clang emits. Returning empty rather than guessing keeps a malformed
/// carrier out of the counts instead of into them.
std::string annotationString(const Value *Op) {
  const Value *V = Op->stripPointerCasts();
  const auto *GV = dyn_cast<GlobalVariable>(V);
  if (!GV || !GV->hasInitializer()) return std::string();
  const auto *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer());
  if (!CDA || !CDA->isCString()) return std::string();
  return CDA->getAsCString().str();
}

bool matchesPrefix(const std::string &S, const std::string &Prefix) {
  if (S.empty()) return false;
  if (Prefix.empty()) return true;
  return S.size() >= Prefix.size() && S.compare(0, Prefix.size(), Prefix) == 0;
}

void sortUnique(std::vector<std::string> &Xs) {
  std::sort(Xs.begin(), Xs.end());
  Xs.erase(std::unique(Xs.begin(), Xs.end()), Xs.end());
}

/// Walk @llvm.global.annotations, calling `Visit(annotatedValue, string)` for
/// every well-formed entry.
template <typename FnT>
void forEachGlobalAnnotation(const Module &M, FnT Visit) {
  const GlobalVariable *GA = M.getNamedGlobal("llvm.global.annotations");
  if (!GA || !GA->hasInitializer()) return;
  const auto *Arr = dyn_cast<ConstantArray>(GA->getInitializer());
  if (!Arr) return;
  for (const Use &U : Arr->operands()) {
    const auto *CS = dyn_cast<ConstantStruct>(U.get());
    if (!CS || CS->getNumOperands() < 2) continue;
    const Value *Annotated = CS->getOperand(0)->stripPointerCasts();
    std::string S = annotationString(CS->getOperand(1));
    if (S.empty()) continue;
    Visit(Annotated, S);
  }
}

bool isAnnotationIntrinsic(const CallBase &CB) {
  const Function *Callee = CB.getCalledFunction();
  if (!Callee) return false;
  const Intrinsic::ID ID = Callee->getIntrinsicID();
  return ID == Intrinsic::var_annotation || ID == Intrinsic::ptr_annotation;
}

} // namespace

Json UnitMetadata::toJson() const {
  Json J = Json::object();
  J.set("unitPresent", Json::boolean(UnitPresent));
  J.set("present", Json::integer(present()));
  J.set("functionAnnotations", Json::integer(FunctionAnnotations));
  J.set("localAnnotations", Json::integer(LocalAnnotations));
  J.set("nonMatchingAnnotations", Json::integer(NonMatchingAnnotations));
  Json A = Json::array();
  for (const std::string &S : Strings) A.push(Json::str(S));
  J.set("strings", std::move(A));
  return J;
}

Json ModuleMetadata::toJson() const {
  Json J = Json::object();
  J.set("carrierPresent", Json::boolean(CarrierPresent));
  J.set("present", Json::integer(present()));
  J.set("functionAnnotations", Json::integer(FunctionAnnotations));
  J.set("localAnnotations", Json::integer(LocalAnnotations));
  J.set("nonMatchingAnnotations", Json::integer(NonMatchingAnnotations));
  Json F = Json::array();
  for (const std::string &S : AnnotatedFunctions) F.push(Json::str(S));
  J.set("annotatedFunctions", std::move(F));
  Json A = Json::array();
  for (const std::string &S : Strings) A.push(Json::str(S));
  J.set("strings", std::move(A));
  return J;
}

UnitMetadata collectUnitMetadata(const Function &F, const MetadataConfig &C) {
  UnitMetadata U;
  U.UnitPresent = !F.isDeclaration();

  forEachGlobalAnnotation(*F.getParent(), [&](const Value *Annotated,
                                              const std::string &S) {
    if (Annotated != &F) return;
    if (matchesPrefix(S, C.Prefix)) {
      U.FunctionAnnotations++;
      U.Strings.push_back(S);
    } else {
      U.NonMatchingAnnotations++;
    }
  });

  // A declaration has no body to walk; the function-level count above is still
  // meaningful for it, which is why this returns rather than starting empty.
  if (!U.UnitPresent) {
    sortUnique(U.Strings);
    return U;
  }

  for (const Instruction &I : instructions(F)) {
    const auto *CB = dyn_cast<CallBase>(&I);
    if (!CB || !isAnnotationIntrinsic(*CB)) continue;
    if (CB->arg_size() < 2) continue;
    std::string S = annotationString(CB->getArgOperand(1));
    if (S.empty()) continue;
    if (matchesPrefix(S, C.Prefix)) {
      U.LocalAnnotations++;
      U.Strings.push_back(S);
    } else {
      U.NonMatchingAnnotations++;
    }
  }

  sortUnique(U.Strings);
  return U;
}

ModuleMetadata collectModuleMetadata(const Module &M, const MetadataConfig &C) {
  ModuleMetadata R;

  const GlobalVariable *GA = M.getNamedGlobal("llvm.global.annotations");
  if (GA && GA->hasInitializer()) R.CarrierPresent = true;

  forEachGlobalAnnotation(M, [&](const Value *Annotated, const std::string &S) {
    if (!matchesPrefix(S, C.Prefix)) {
      R.NonMatchingAnnotations++;
      return;
    }
    R.FunctionAnnotations++;
    R.Strings.push_back(S);
    if (const auto *F = dyn_cast<Function>(Annotated))
      R.AnnotatedFunctions.push_back(F->getName().str());
  });

  for (const Function &F : M) {
    if (F.isDeclaration()) continue;
    for (const Instruction &I : instructions(F)) {
      const auto *CB = dyn_cast<CallBase>(&I);
      if (!CB || !isAnnotationIntrinsic(*CB)) continue;
      R.CarrierPresent = true;
      if (CB->arg_size() < 2) continue;
      std::string S = annotationString(CB->getArgOperand(1));
      if (S.empty()) continue;
      if (matchesPrefix(S, C.Prefix)) {
        R.LocalAnnotations++;
        R.Strings.push_back(S);
      } else {
        R.NonMatchingAnnotations++;
      }
    }
  }

  sortUnique(R.Strings);
  sortUnique(R.AnnotatedFunctions);
  return R;
}

} // namespace irck
