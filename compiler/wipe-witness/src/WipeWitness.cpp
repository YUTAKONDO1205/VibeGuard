// WipeWitness -- a read-only pass plugin that counts what is left of WipePin's
// repairs at the start and at the end of clang's optimisation pipeline.
//
// WipePin (../../llvm-repair/src/WipePin.cpp) runs once, at the pipeline-start
// extension point, and writes its record there. Whatever the optimiser does to
// a repair afterwards, the record does not change. Three times a placement rule
// in WipePin was wrong in a way the record could not show; in one of them the
// barrier went into a block no path reaches, the optimiser deleted the block,
// and the record still counted the barrier. This plugin is a second reading,
// by code that shares nothing with WipePin: it counts the repair's shapes in
// each function directly after WipePin has run, and again at the last
// extension point before code generation, and writes both counts to a record
// of its own (wipe-witness-v1). scripts/witness_check.py compares that record
// with WipePin's.
//
// It is an observer. It changes no instruction, no attribute and no metadata,
// computes no analysis through the pass manager, and returns
// PreservedAnalyses::all(); the -S output with it loaded is meant to be the
// -S output without it, byte for byte (README, Measured).
//
// What it counts, per function:
//   barriers             a call of `asm sideeffect "", "r,~{memory}"` with one
//                        pointer argument and no result: the exact shape
//                        WipePin's two barrier writers build (InlineAsm::get
//                        with an empty string, constraints "r,~{memory}",
//                        hasSideEffects true)
//   otherMemoryAsm       any other side-effecting inline asm whose constraints
//                        clobber memory
//   volatileZeroMemsets  a call of llvm.memset.* or llvm.memset.inline.* whose
//                        fill is the constant zero and whose volatile flag is
//                        the constant true -- the shape of WipePin's pin, and of
//                        its repair of a copy from an all-zero constant
//   volatileZeroStores   a volatile store of a null constant (not a shape
//                        WipePin makes; counted so a reader can see a wipe the
//                        source already kept)
//
// The memset is recognised by the callee's name, not by its intrinsic id, so a
// difference in intrinsic numbering cannot make it invisible. The plugin still
// refuses a module whose llvm.ident names another clang major version than the
// one it was built against: a plugin loaded into another clang is outside
// what was measured.
//
// What it cannot see (README):
//   - code generation. A store the instruction selector drops after the end
//     pass has run is not seen; the end count is of the IR handed to it.
//   - who placed a barrier. A barrier with WipePin's shape that the source
//     already had is counted the same way. On x86-64 clang appends
//     ~{dirflag},~{fpsr},~{flags} to every GNU asm statement, so a barrier
//     written in C there has another constraint string (measured, README);
//     that is a property of the target, not something this plugin checks.
//   - whether a barrier protects a wipe. A barrier on a path the wipe does not
//     take survives, and is counted.
//
// The order of the two plugins matters: the start count is meant to be taken
// directly after WipePin. clang runs pipeline-start callbacks in the order the
// plugins were loaded, so WipePin must come first on the command line. The
// plugin watches the pass instrumentation for WipePinPass and writes the order
// it saw into the record; witness_check.py refuses any order but
// "wipepin-first".

#include "llvm/ADT/Any.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

using namespace llvm;

// Everything is in an anonymous namespace: clang loads pass plugins with
// RTLD_GLOBAL, and a class with external linkage that WipePin also defined
// under the same name would let one plugin's code run in place of the other's.
namespace {

const char *const SchemaVersion = "wipe-witness-v1";
const char *const OutVar = "WWIT_OUT";
const int64_t BuiltMajor = LLVM_VERSION_MAJOR;

bool hasPrefix(StringRef S, StringRef P) {
  return S.size() >= P.size() && S.substr(0, P.size()) == P;
}

struct Counts {
  int64_t Barriers = 0;
  int64_t OtherMemoryAsm = 0;
  int64_t VolatileZeroMemsets = 0;
  int64_t VolatileZeroStores = 0;
};

bool isZeroInt(const Value *V) {
  const auto *C = dyn_cast<ConstantInt>(V);
  return C && C->isZero();
}

/// WipePin's barrier: `call void asm sideeffect "", "r,~{memory}"(ptr %p)`.
/// The dialect is not compared: WipePin builds the asm with the default
/// (AT&T), and an empty string means the same in either.
bool isWipePinBarrier(const CallBase &CB, const InlineAsm &IA) {
  return IA.hasSideEffects() && StringRef(IA.getAsmString()).empty() &&
         StringRef(IA.getConstraintString()) == "r,~{memory}" &&
         CB.getType()->isVoidTy() && CB.arg_size() == 1 &&
         CB.getArgOperand(0)->getType()->isPointerTy();
}

/// llvm.memset.<types> and llvm.memset.inline.<types> take (dest, value,
/// length, isvolatile). llvm.memset.element.unordered.atomic takes an element
/// size where the others take the volatile flag, and is not counted.
bool isVolatileZeroMemset(const CallBase &CB) {
  const Function *Callee = CB.getCalledFunction();
  if (!Callee) return false;
  const StringRef N = Callee->getName();
  if (!hasPrefix(N, "llvm.memset.") || hasPrefix(N, "llvm.memset.element."))
    return false;
  if (CB.arg_size() < 4) return false;
  const auto *Vol = dyn_cast<ConstantInt>(CB.getArgOperand(3));
  return Vol && Vol->getType()->isIntegerTy(1) && Vol->isOne() &&
         isZeroInt(CB.getArgOperand(1));
}

Counts countIn(const Function &F) {
  Counts C;
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      if (const auto *SI = dyn_cast<StoreInst>(&I)) {
        if (SI->isVolatile())
          if (const auto *K = dyn_cast<Constant>(SI->getValueOperand()))
            if (K->isNullValue()) C.VolatileZeroStores++;
        continue;
      }
      const auto *CB = dyn_cast<CallBase>(&I);
      if (!CB) continue;
      if (CB->isInlineAsm()) {
        const auto *IA = cast<InlineAsm>(CB->getCalledOperand());
        if (isWipePinBarrier(*CB, *IA))
          C.Barriers++;
        else if (IA->hasSideEffects() &&
                 StringRef(IA->getConstraintString()).find("~{memory}") !=
                     StringRef::npos)
          C.OtherMemoryAsm++;
        continue;
      }
      if (isVolatileZeroMemset(*CB)) C.VolatileZeroMemsets++;
    }
  }
  return C;
}

// --- llvm.ident, read the way WipePin's record reads it ----------------------
// (../../schema/wipe-pin.md section 14.7): every parenthesised group and the
// whitespace before it removed, surrounding whitespace trimmed; the major
// version is the integer after the first "clang version " followed by a digit.

bool isIdentSpace(char C) {
  return C == ' ' || C == '\t' || C == '\n' || C == '\r' || C == '\f' || C == '\v';
}

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

bool clangMajorOf(const std::string &Ident, int64_t &Major) {
  static const std::string Key = "clang version ";
  for (size_t At = Ident.find(Key); At != std::string::npos;
       At = Ident.find(Key, At + 1)) {
    size_t I = At + Key.size();
    if (I >= Ident.size() || Ident[I] < '0' || Ident[I] > '9') continue;
    int64_t V = 0;
    for (; I < Ident.size() && Ident[I] >= '0' && Ident[I] <= '9'; ++I)
      V = V < 100000000 ? V * 10 + (Ident[I] - '0') : V;
    Major = V;
    return true;
  }
  return false;
}

struct Ident {
  bool Have = false;
  std::string Text;
  bool HaveMajor = false;
  int64_t Major = 0;
};

Ident identOf(const Module &M) {
  Ident Id;
  const NamedMDNode *N = M.getNamedMetadata("llvm.ident");
  if (!N || N->getNumOperands() == 0) return Id;
  const MDNode *Op = N->getOperand(0);
  if (!Op || Op->getNumOperands() == 0) return Id;
  const auto *MS = dyn_cast_or_null<MDString>(Op->getOperand(0));
  if (!MS) return Id;
  Id.Have = true;
  Id.Text = stripIdent(MS->getString());
  Id.HaveMajor = clangMajorOf(Id.Text, Id.Major);
  return Id;
}

// --- the record --------------------------------------------------------------

void putString(std::string &O, StringRef S) {
  static const char *Hex = "0123456789abcdef";
  O.push_back('"');
  for (unsigned char C : S) {
    switch (C) {
    case '"': O += "\\\""; break;
    case '\\': O += "\\\\"; break;
    case '\n': O += "\\n"; break;
    case '\r': O += "\\r"; break;
    case '\t': O += "\\t"; break;
    case '\b': O += "\\b"; break;
    case '\f': O += "\\f"; break;
    default:
      if (C < 0x20) {
        O += "\\u00";
        O.push_back(Hex[(C >> 4) & 0xF]);
        O.push_back(Hex[C & 0xF]);
      } else {
        O.push_back(static_cast<char>(C));
      }
    }
  }
  O.push_back('"');
}

void putCounts(std::string &O, const Counts &C) {
  O += "{\"barriers\":" + std::to_string(C.Barriers) +
       ",\"otherMemoryAsm\":" + std::to_string(C.OtherMemoryAsm) +
       ",\"volatileZeroMemsets\":" + std::to_string(C.VolatileZeroMemsets) +
       ",\"volatileZeroStores\":" + std::to_string(C.VolatileZeroStores) + "}";
}

/// One function of the record. Start is absent for a function the end pass
/// found and the start pass did not (a clone made by the optimiser); End is
/// absent unless the function is still a definition at the end.
struct Entry {
  std::string Name;
  bool HaveStart = false;
  Counts Start;
  bool HaveEnd = false;
  Counts End;
  const char *EndState = "absent"; // "defined", "declaration" or "absent"
};

/// State shared by the load-time callback, the two passes and the
/// instrumentation callback of one PassBuilder (one compile).
struct State {
  std::string OutPath;
  bool HaveInstrumentation = false;
  bool WipePinRan = false;          // set when WipePinPass is about to run
  bool StartRan = false;
  bool WipePinRanBeforeStart = false;
  bool OrderSaid = false;
  unsigned ModulesSeen = 0;
  std::string ModuleName;
  Ident Id;
  int64_t Speedup = 0;
  int64_t Size = 0;
  std::vector<Entry> Entries;          // the start pass's functions, in order
  std::map<std::string, size_t> Index; // name -> position in Entries
};

const char *orderOf(const State &S, bool AtEnd) {
  if (!S.HaveInstrumentation) return "unknown";
  if (S.WipePinRanBeforeStart) return "wipepin-first";
  if (AtEnd && S.WipePinRan) return "witness-first";
  return "no-wipepin";
}

std::string recordText(const State &S, bool EndReached) {
  std::string O;
  O += "{\"schemaVersion\":";
  putString(O, SchemaVersion);
  O += ",\"component\":\"WipeWitness\",\"module\":";
  putString(O, S.ModuleName);
  O += ",\"ident\":";
  if (S.Id.Have) putString(O, S.Id.Text);
  else O += "null";
  O += ",\"identMajor\":";
  O += S.Id.HaveMajor ? std::to_string(S.Id.Major) : std::string("null");
  O += ",\"llvmMajor\":" + std::to_string(BuiltMajor);
  O += ",\"llvmVersion\":";
  putString(O, LLVM_VERSION_STRING);
  O += ",\"optLevel\":{\"speedup\":" + std::to_string(S.Speedup) +
       ",\"size\":" + std::to_string(S.Size) + "}";
  O += ",\"order\":";
  putString(O, orderOf(S, EndReached));
  O += std::string(",\"endReached\":") + (EndReached ? "true" : "false");
  O += ",\"functions\":[";
  bool First = true;
  for (const Entry &E : S.Entries) {
    if (!First) O.push_back(',');
    First = false;
    O += "{\"name\":";
    putString(O, E.Name);
    O += ",\"start\":";
    if (E.HaveStart) putCounts(O, E.Start);
    else O += "null";
    O += ",\"end\":";
    if (EndReached && E.HaveEnd) putCounts(O, E.End);
    else O += "null";
    O += ",\"endState\":";
    if (EndReached) putString(O, E.EndState);
    else O += "null";
    O.push_back('}');
  }
  O += "]}\n";
  return O;
}

void writeRecord(const State &S, bool EndReached) {
  std::error_code EC;
  raw_fd_ostream Out(S.OutPath, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "WipeWitness: cannot write the record to " << OutVar << " ("
           << EC.message() << "); nothing records this compile\n";
    return;
  }
  Out << recordText(S, EndReached);
}

class WitnessStartPass : public PassInfoMixin<WitnessStartPass> {
public:
  WitnessStartPass(std::shared_ptr<State> S, OptimizationLevel L)
      : St(std::move(S)), Level(L) {}
  static StringRef name() { return "WipeWitnessStart"; }
  static bool isRequired() { return true; }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    State &S = *St;
    const Ident Id = identOf(M);
    if (Id.HaveMajor && Id.Major != BuiltMajor) {
      // Nothing is counted and nothing is written: the record left at the
      // path was removed when the plugin loaded, so "no record" is the truth.
      errs() << "WipeWitness: refusing to count: the module was produced by "
                "clang "
             << Id.Major << " and this plugin was built against LLVM "
             << BuiltMajor << "\n";
      return PreservedAnalyses::all();
    }
    if (++S.ModulesSeen > 1)
      errs() << "WipeWitness: a second module reached the start pass in one "
                "process; the record describes the last one only\n";
    S.StartRan = true;
    S.WipePinRanBeforeStart = S.WipePinRan;
    S.ModuleName = sys::path::filename(M.getModuleIdentifier()).str();
    S.Id = Id;
    S.Speedup = Level.getSpeedupLevel();
    S.Size = Level.getSizeLevel();
    S.Entries.clear();
    S.Index.clear();
    for (const Function &F : M) {
      if (F.isDeclaration()) continue;
      Entry E;
      E.Name = F.getName().str();
      E.HaveStart = true;
      E.Start = countIn(F);
      S.Index[E.Name] = S.Entries.size();
      S.Entries.push_back(std::move(E));
    }
    // Written now as well as at the end: a pipeline whose end pass never runs
    // leaves a record that says so (endReached: false) rather than none.
    writeRecord(S, /*EndReached=*/false);
    return PreservedAnalyses::all();
  }

private:
  std::shared_ptr<State> St;
  OptimizationLevel Level;
};

class WitnessEndPass : public PassInfoMixin<WitnessEndPass> {
public:
  explicit WitnessEndPass(std::shared_ptr<State> S) : St(std::move(S)) {}
  static StringRef name() { return "WipeWitnessEnd"; }
  static bool isRequired() { return true; }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    State &S = *St;
    if (!S.StartRan) {
      // An LTO backend runs this extension point and never pipeline start;
      // so does a refused module. There is no start count to pair with.
      errs() << "WipeWitness: the end pass ran without the start pass in this "
                "process (an LTO link, or a refused module); no record\n";
      return PreservedAnalyses::all();
    }
    for (Entry &E : S.Entries) {
      E.HaveEnd = false;
      E.EndState = "absent";
      const Function *F = M.getFunction(E.Name);
      if (!F) continue;
      if (F->isDeclaration()) {
        E.EndState = "declaration";
        continue;
      }
      E.EndState = "defined";
      E.HaveEnd = true;
      E.End = countIn(*F);
    }
    for (const Function &F : M) {
      if (F.isDeclaration()) continue;
      const std::string N = F.getName().str();
      if (S.Index.count(N)) continue;
      Entry E;
      E.Name = N;
      E.HaveEnd = true;
      E.End = countIn(F);
      E.EndState = "defined";
      S.Index[N] = S.Entries.size();
      S.Entries.push_back(std::move(E));
    }
    const char *Order = orderOf(S, /*AtEnd=*/true);
    if (StringRef(Order) == "witness-first" && !S.OrderSaid) {
      S.OrderSaid = true;
      errs() << "WipeWitness: this plugin's start pass ran before WipePinPass; "
                "load WipePin first (its -fpass-plugin before this one's). The "
                "record says order \"witness-first\" and the checker refuses "
                "it\n";
    }
    writeRecord(S, /*EndReached=*/true);
    return PreservedAnalyses::all();
  }

private:
  std::shared_ptr<State> St;
};

void registerCallbacks(PassBuilder &PB) {
  const char *Out = std::getenv(OutVar);
  if (!Out || !*Out) {
    errs() << "WipeWitness: " << OutVar
           << " is not set; the plugin is loaded and does nothing\n";
    return;
  }
  auto S = std::make_shared<State>();
  S->OutPath = Out;
  // A record an earlier compile left at the path must not stand in for this
  // one. Removed here, at load, as WipePin removes its own.
  if (std::error_code EC = sys::fs::remove(S->OutPath, /*IgnoreNonExisting=*/true)) {
    errs() << "WipeWitness: refusing to install: cannot remove the file at "
           << OutVar << " (" << EC.message() << ")\n";
    return;
  }
  if (PassInstrumentationCallbacks *PIC = PB.getPassInstrumentationCallbacks()) {
    S->HaveInstrumentation = true;
    // Reads the pass's name only; the IR unit is not looked at.
    PIC->registerBeforeNonSkippedPassCallback([S](StringRef P, Any) {
      if (P == "WipePinPass") S->WipePinRan = true;
    });
  }
  PB.registerPipelineStartEPCallback(
      [S](ModulePassManager &MPM, OptimizationLevel L) {
        MPM.addPass(WitnessStartPass(S, L));
      });
#if LLVM_VERSION_MAJOR >= 20
  PB.registerOptimizerLastEPCallback(
      [S](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
        MPM.addPass(WitnessEndPass(S));
      });
#else
  PB.registerOptimizerLastEPCallback(
      [S](ModulePassManager &MPM, OptimizationLevel) {
        MPM.addPass(WitnessEndPass(S));
      });
#endif
}

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "WipeWitness", LLVM_VERSION_STRING,
          registerCallbacks};
}
