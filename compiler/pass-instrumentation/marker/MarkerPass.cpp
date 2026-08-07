//===- MarkerPass.cpp - a deliberately invasive experiment pass -----------===//
//
// This pass exists to be caught.
//
// It is the positive control for the plugin integrity check in
// compiler/driver/plugin-integrity/: a check that never fires is not a check,
// so there has to be something that makes it fire. MarkerPass is that
// something. It is loaded the same way a hostile pass plugin would be
// (-fpass-plugin=), it runs at the same extension point one would use, and it
// leaves the same kind of trace: symbols in the object file that no line of the
// translation unit asks for.
//
// What it does is harmless on purpose. It adds one function and one global in
// a private section, neither of which is called or read by anything. The point
// is not the payload, it is that the payload arrives at all without the source
// changing, and that the integrity check notices.
//
// Two properties are load-bearing and should not be "cleaned up":
//
//   1. It registers on the pipeline-start extension point, so merely passing
//      -fpass-plugin= is enough to make it run. A plugin that only registers a
//      named pass would need -passes= as well, and would therefore not model
//      the thing being defended against, which is a plugin that runs because it
//      was loaded.
//
//   2. The global is appended to llvm.compiler.used. Without that, later
//      passes drop an unreferenced constant and the object comes out clean,
//      which would make the positive control silently stop controlling for
//      anything.
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace {

// Names chosen to be recognisable in `nm` output and to belong to no real
// library. The integrity check's object-diff step looks for exactly these.
constexpr const char *kMarkerFn = "__marker_pass_present";
constexpr const char *kMarkerVar = "__marker_pass_stamp";
constexpr const char *kMarkerSection = ".marker_pass";

// Arbitrary, but fixed: a build that contains this constant contains it
// because this pass ran, not because a compiler decided something.
constexpr uint64_t kMarkerStamp = 0x4d41524b45523031ULL; // "MARKER01"

struct MarkerPass : PassInfoMixin<MarkerPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = false;
    LLVMContext &Ctx = M.getContext();

    // A module can be visited more than once in a session; adding the marker
    // twice would produce a name collision and a renamed symbol, which reads
    // like a different finding than the one being demonstrated.
    if (!M.getNamedValue(kMarkerFn)) {
      FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);
      Function *F =
          Function::Create(FT, GlobalValue::ExternalLinkage, kMarkerFn, &M);
      F->setDoesNotThrow();
      BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
      IRBuilder<> B(BB);
      B.CreateRetVoid();
      Changed = true;
    }

    if (!M.getNamedGlobal(kMarkerVar)) {
      Type *I64 = Type::getInt64Ty(Ctx);
      auto *GV = new GlobalVariable(
          M, I64, /*isConstant=*/true, GlobalValue::ExternalLinkage,
          ConstantInt::get(I64, kMarkerStamp), kMarkerVar);
      GV->setSection(kMarkerSection);
      GV->setAlignment(Align(8));
      // Keep it alive through globaldce; see the header comment.
      appendToCompilerUsed(M, {GV});
      Changed = true;
    }

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  // Run even when the module is marked optnone.
  static bool isRequired() { return true; }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "MarkerPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // Runs on load alone. This is the behaviour being defended against.
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(MarkerPass());
                });
            // Also addressable by name, so the pass can be exercised through
            // `opt -passes=marker-pass` without a driver in the way.
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "marker-pass") {
                    MPM.addPass(MarkerPass());
                    return true;
                  }
                  return false;
                });
          }};
}
