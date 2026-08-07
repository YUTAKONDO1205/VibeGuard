//===- Census.cpp ---------------------------------------------------------===//
//
// Part of the introduction observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//

#include "Census.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace introobs {

static const char *const SCHEMA = "introduction-observer-v1";
static const char *const MODULE_SCOPE = "(module)";

const char *stateName(State S) {
  switch (S) {
  case State::NotObserved: return "NOT_OBSERVED";
  case State::Present: return "PRESENT";
  case State::Absent: return "ABSENT";
  case State::Lost: return "LOST";
  case State::Reintroduced: return "REINTRODUCED";
  case State::NotApplicable: return "NOT_APPLICABLE";
  }
  return "NOT_OBSERVED";
}

const char *kindName(Kind K) {
  switch (K) {
  case Kind::Symbol: return "symbol";
  case Kind::ExternalCall: return "extcall";
  case Kind::Initialiser: return "initialiser";
  case Kind::Section: return "section";
  }
  return "symbol";
}

/// Tabs and newlines would break the log format, and a name can in principle
/// contain either. Replaced rather than quoted: the reader is line-oriented and
/// a quoting scheme it has to unpick is a second thing that can be wrong.
static std::string sanitise(StringRef S) {
  std::string Out;
  Out.reserve(S.size());
  for (char C : S) Out.push_back((C == '\t' || C == '\n' || C == '\r') ? ' ' : C);
  return Out;
}

static std::string elementKey(StringRef Scope, Kind K, StringRef Name) {
  std::string Out;
  Out.reserve(Scope.size() + Name.size() + 8);
  Out.append(Scope.begin(), Scope.end());
  Out.push_back('\x1f');
  Out.append(kindName(K));
  Out.push_back('\x1f');
  Out.append(Name.begin(), Name.end());
  return Out;
}

Census::Census(Config C) : Cfg(std::move(C)) {
  std::error_code EC;
  auto S = std::make_unique<raw_fd_ostream>(Cfg.OutPath, EC, sys::fs::OF_Append);
  if (!EC) Out = std::move(S);
}

Census::~Census() { finish(); }

ScopeRecord &Census::scopeFor(StringRef Name) {
  auto It = Scopes.find(Name.str());
  if (It != Scopes.end()) return It->second;
  ScopeRecord R;
  R.Name = Name.str();
  auto Ins = Scopes.emplace(R.Name, std::move(R));
  ScopeOrder.push_back(Ins.first->first);
  return Ins.first->second;
}

void Census::handshake(const Module &M) {
  if (Announced || !Out) return;
  Announced = true;
  // The file name, never the path. The module identifier is whatever the
  // driver was handed, and on a checkout reached over a mount that is an
  // absolute path with an account name in it -- which interfaces.md §5 forbids
  // anywhere in a record. Caught by the test that greps the log for one.
  LastModuleId = sys::path::filename(M.getModuleIdentifier()).str();
  std::string W;
  if (Cfg.Watched.Symbols) W += "symbols,";
  if (Cfg.Watched.ExternalCalls) W += "extcalls,";
  if (Cfg.Watched.Initialisers) W += "initialisers,";
  if (Cfg.Watched.Sections) W += "sections,";
  if (!W.empty()) W.pop_back();
  *Out << "HANDSHAKE\t" << SCHEMA << '\t' << sanitise(LastModuleId) << '\t'
       << modeName(Cfg.ObsMode) << '\t' << sanitise(Cfg.ControlFn) << '\t' << W
       << '\n';
  Out->flush();
}

void Census::passRecord(uint64_t S, StringRef Phase, StringRef PassID,
                        StringRef UnitKind, StringRef UnitName) {
  PassesSeen++;
  if (Out && Cfg.ObsMode == Mode::Trace) {
    *Out << "PASS\t" << S << '\t' << Phase << '\t' << sanitise(PassID) << '\t'
         << UnitKind << '\t' << sanitise(UnitName) << '\n';
  }
}

void Census::skipRecord(uint64_t S, StringRef Phase, StringRef PassID) {
  Skipped++;
  if (Out && Cfg.ObsMode == Mode::Trace) {
    *Out << "SKIP\t" << S << '\t' << Phase << '\t' << sanitise(PassID) << '\n';
  }
}

// --- the census -------------------------------------------------------------

void Census::syncModuleScope(uint64_t S, StringRef Phase, StringRef PassID,
                             StringRef UnitKind, StringRef UnitName,
                             const Module &M) {
  handshake(M);
  Observed Now;

  if (Cfg.Watched.Symbols) {
    // A definition, not a declaration. A `declare` line is a name the module
    // mentions, not a symbol it introduces; counting it here would be the same
    // error the oracle rule forbids on the loss side (interfaces.md §4).
    for (const Function &F : M)
      if (!F.isDeclaration())
        Now[{Kind::Symbol, F.getName().str()}] = 1;
    for (const GlobalVariable &G : M.globals())
      if (!G.isDeclaration())
        Now[{Kind::Symbol, G.getName().str()}] = 1;
  }

  if (Cfg.Watched.Sections) {
    for (const Function &F : M)
      if (!F.isDeclaration() && F.hasSection())
        Now[{Kind::Section, F.getSection().str()}] = 1;
    for (const GlobalVariable &G : M.globals())
      if (!G.isDeclaration() && G.hasSection())
        Now[{Kind::Section, G.getSection().str()}] = 1;
  }

  if (Cfg.Watched.Initialisers) {
    // A static initialiser, as the IR spells it: an entry of
    // @llvm.global_ctors, which is `{ i32 priority, ptr fn, ptr assoc }`.
    if (const GlobalVariable *GC = M.getNamedGlobal("llvm.global_ctors")) {
      if (GC->hasInitializer()) {
        if (const auto *Arr = dyn_cast<ConstantArray>(GC->getInitializer())) {
          for (unsigned I = 0, E = Arr->getNumOperands(); I != E; ++I) {
            const auto *Entry = dyn_cast<ConstantStruct>(Arr->getOperand(I));
            if (!Entry || Entry->getNumOperands() < 2) continue;
            const Constant *Fn = Entry->getOperand(1)->stripPointerCasts();
            if (!Fn || !Fn->hasName()) continue;
            Now[{Kind::Initialiser, Fn->getName().str()}] += 1;
          }
        }
      }
    }
  }

  applyScope(MODULE_SCOPE, S, Phase, PassID, UnitKind, UnitName, Now);
}

void Census::syncFunctionScope(uint64_t S, StringRef Phase, StringRef PassID,
                               StringRef UnitKind, StringRef UnitName,
                               const Function &F) {
  if (!Cfg.Watched.ExternalCalls) return;
  Observed Now;

  // The oracle rule, on the introduction side. An external call is a call site
  // whose callee has no body in this module -- a `CallBase` walked in the IR
  // object model, resolved through `getCalledFunction`. It is not the presence
  // of a `declare` line, which survives long after the last call to it is gone
  // and which a name search would keep reporting.
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      const auto *CB = dyn_cast<CallBase>(&I);
      if (!CB) continue;
      const Function *Callee = CB->getCalledFunction();
      if (!Callee) continue;              // indirect: no name to attribute to
      if (!Callee->isDeclaration()) continue;  // defined here: not external
      Now[{Kind::ExternalCall, Callee->getName().str()}] += 1;
    }
  }

  applyScope(F.getName(), S, Phase, PassID, UnitKind, UnitName, Now);
}

void Census::applyScope(StringRef ScopeName, uint64_t S, StringRef Phase,
                        StringRef PassID, StringRef UnitKind, StringRef UnitName,
                        const Observed &Now) {
  if (!Out) return;
  ScopeRecord &Sc = scopeFor(ScopeName);

  const bool FirstLook = Sc.Observations == 0;
  const uint64_t PrevSeq = Sc.LastObsSeq;
  const std::string PrevPhase = Sc.LastObsPhase;
  const std::string PrevPass = Sc.LastObsPass;
  const std::string PrevAfterPass = Sc.LastAfterPass;
  const long FnIdx = (Phase == "after" && UnitKind == "function")
                         ? static_cast<long>(Sc.FnAfterObs)
                         : -1;

  auto note = [&](ElementRecord &R, State New, unsigned Count, bool Changed) {
    R.Cur = New;
    if (!R.Hist.empty() && R.Hist.back().St == New && R.Hist.back().Count == Count) {
      // Same answer as last time. Extend the run rather than starting a new
      // entry: the series is the sequence of states, and repeating one is not a
      // new state. `Repeats` keeps the count of observations honest.
      HistEntry &Back = R.Hist.back();
      Back.Repeats++;
      Back.LastSeq = S;
      Back.LastPass = PassID.str();
    } else {
      HistEntry E;
      E.Seq = S;
      E.LastSeq = S;
      E.Phase = Phase.str();
      E.Pass = PassID.str();
      E.LastPass = PassID.str();
      E.Count = Count;
      E.Repeats = 1;
      E.St = New;
      R.Hist.push_back(std::move(E));
    }
    ElemRecords++;
    if (Cfg.ObsMode == Mode::Trace || Changed) {
      *Out << "ELEM\t" << S << '\t' << Phase << '\t' << sanitise(PassID) << '\t'
           << UnitKind << '\t' << sanitise(UnitName) << '\t'
           << sanitise(ScopeName) << '\t' << kindName(R.ElemKind) << '\t'
           << sanitise(R.Name) << '\t' << Count << '\t' << stateName(New) << '\t'
           << (Changed ? 1 : 0) << '\n';
    }
  };

  // --- things that are here now ------------------------------------------
  for (const auto &KV : Now) {
    const Kind K = KV.first.first;
    const std::string &Name = KV.first.second;
    const unsigned Count = KV.second;
    const std::string Key = elementKey(ScopeName, K, Name);

    auto It = Elements.find(Key);
    if (It == Elements.end()) {
      ElementRecord R;
      R.Scope = ScopeName.str();
      R.ElemKind = K;
      R.Name = Name;
      auto Ins = Elements.emplace(Key, std::move(R));
      ElementOrder.push_back(Ins.first->first);
      It = Ins.first;

      ElementRecord &Rec = It->second;
      Rec.EverPresent = true;
      Rec.IntroEpisodes = 1;
      Rec.HaveFirstIntro = true;
      Rec.FirstIntroSeq = S;
      Rec.FirstIntroPhase = Phase.str();
      Rec.FirstIntroPass = PassID.str();
      Rec.FirstIntroUnitKind = UnitKind.str();
      Rec.FirstIntroUnit = UnitName.str();
      Rec.FirstIntroPrevAfterPass = PrevAfterPass;
      Rec.FirstIntroFnIdx = FnIdx;
      Rec.AtEntry = FirstLook;

      if (!FirstLook) {
        // A measured absence, at the seq it was measured. The previous
        // observation enumerated this whole scope and this element was not in
        // it, which is what makes ABSENT -> PRESENT a series rather than an
        // assumption about what came before.
        HistEntry A;
        A.Seq = PrevSeq;
        A.LastSeq = PrevSeq;
        A.Phase = PrevPhase;
        A.Pass = PrevPass;
        A.LastPass = PrevPass;
        A.Count = 0;
        A.Repeats = 1;
        A.St = State::Absent;
        Rec.Hist.push_back(std::move(A));
      }
      note(Rec, State::Present, Count, /*Changed=*/true);

      *Out << "INTRO\t" << S << '\t' << Phase << '\t' << sanitise(PassID) << '\t'
           << UnitKind << '\t' << sanitise(UnitName) << '\t'
           << sanitise(ScopeName) << '\t' << kindName(K) << '\t'
           << sanitise(Name) << '\t' << (FirstLook ? 1 : 0) << '\t'
           << sanitise(PrevAfterPass) << '\t' << FnIdx << '\n';
      continue;
    }

    ElementRecord &Rec = It->second;
    const bool WasGone = (Rec.Cur == State::Lost);
    if (WasGone) {
      Rec.EverReintroduced = true;
      Rec.IntroEpisodes++;
      note(Rec, State::Reintroduced, Count, /*Changed=*/true);
    } else {
      const bool CountChanged =
          Rec.Hist.empty() ? true : Rec.Hist.back().Count != Count;
      note(Rec, Rec.Cur == State::Reintroduced ? State::Reintroduced : State::Present,
           Count, /*Changed=*/CountChanged);
    }
  }

  // --- things that were here and are not ---------------------------------
  // Only within this scope. A module-wide sweep would report a function's call
  // sites as lost every time some other function's callback fired.
  for (const std::string &Key : ElementOrder) {
    ElementRecord &Rec = Elements[Key];
    if (Rec.Scope != ScopeName) continue;
    if (Rec.Cur == State::Lost || Rec.Cur == State::NotObserved) continue;
    if (Now.count({Rec.ElemKind, Rec.Name})) continue;
    Rec.EverLost = true;
    Rec.LossEpisodes++;
    note(Rec, State::Lost, 0, /*Changed=*/true);
  }

  Sc.Observations++;
  Sc.LastObsSeq = S;
  Sc.LastObsPhase = Phase.str();
  Sc.LastObsPass = PassID.str();
  if (Phase == "after") {
    Sc.LastAfterPass = PassID.str();
    if (UnitKind == "function") Sc.FnAfterObs++;
  }
}

// --- output -----------------------------------------------------------------

void Census::emitSummaryInto(raw_ostream &OS) const {
  for (const std::string &Key : ElementOrder) {
    const ElementRecord &R = Elements.at(Key);
    OS << "SUMMARY\t" << sanitise(R.Scope) << '\t' << kindName(R.ElemKind) << '\t'
       << sanitise(R.Name) << '\t' << R.FirstIntroSeq << '\t'
       << R.FirstIntroPhase << '\t' << sanitise(R.FirstIntroPass) << '\t'
       << R.FirstIntroUnitKind << '\t' << sanitise(R.FirstIntroUnit) << '\t'
       << sanitise(R.FirstIntroPrevAfterPass) << '\t' << R.FirstIntroFnIdx << '\t'
       << (R.AtEntry ? 1 : 0) << '\t' << stateName(R.Cur) << '\t'
       << (R.EverPresent ? 1 : 0) << '\t' << (R.EverLost ? 1 : 0) << '\t'
       << (R.EverReintroduced ? 1 : 0) << '\t' << R.IntroEpisodes << '\t'
       << R.LossEpisodes << '\t' << R.Hist.size() << '\n';
    unsigned Idx = 0;
    for (const HistEntry &H : R.Hist) {
      OS << "HIST\t" << sanitise(R.Scope) << '\t' << kindName(R.ElemKind) << '\t'
         << sanitise(R.Name) << '\t' << Idx++ << '\t' << H.Seq << '\t' << H.Phase
         << '\t' << sanitise(H.Pass) << '\t' << H.Count << '\t'
         << stateName(H.St) << '\t' << H.Repeats << '\t' << H.LastSeq << '\t'
         << sanitise(H.LastPass) << '\n';
    }
  }
}

void Census::writeSummaryFile() {
  std::error_code EC;
  raw_fd_ostream S(Cfg.OutPath + ".summary.tsv", EC, sys::fs::OF_None);
  if (EC) return;
  emitSummaryInto(S);
}

void Census::finish() {
  if (Finished || !Out) return;
  Finished = true;

  emitSummaryInto(*Out);

  // The control's fate, on its own line. A run whose control never appeared, or
  // whose control was lost, is a broken measurement rather than a result, and
  // the reader must be able to see that without reconstructing it.
  const std::string ControlKey =
      elementKey(MODULE_SCOPE, Kind::Symbol, Cfg.ControlFn);
  const auto It = Elements.find(ControlKey);
  const bool ControlSeen = It != Elements.end();
  const char *ControlState = ControlSeen ? stateName(It->second.Cur) : "NOT_OBSERVED";

  *Out << "STATS\t" << PassesSeen << '\t' << ElemRecords << '\t'
       << Elements.size() << '\t' << Scopes.size() << '\t' << Skipped << '\t'
       << modeName(Cfg.ObsMode) << '\t' << (ControlSeen ? 1 : 0) << '\t'
       << ControlState << '\n';
  Out->flush();
  writeSummaryFile();
}

} // namespace introobs
