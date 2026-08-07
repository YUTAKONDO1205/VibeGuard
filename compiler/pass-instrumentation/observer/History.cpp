//===- History.cpp --------------------------------------------------------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//

#include "History.h"
#include "Oracle.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <system_error>

using namespace llvm;

namespace propobs {

static const char *const kSchema = "obs-log-v1";

const char *stateName(State S) {
  switch (S) {
  case State::NotObserved:
    return "NOT_OBSERVED";
  case State::Present:
    return "PRESENT";
  case State::Absent:
    return "ABSENT";
  case State::Lost:
    return "LOST";
  case State::Reintroduced:
    return "REINTRODUCED";
  case State::NotApplicable:
    return "NOT_APPLICABLE";
  }
  return "NOT_OBSERVED";
}

const char *fateName(Fate F) {
  switch (F) {
  case Fate::Live:
    return "LIVE";
  case Fate::BodyRemoved:
    return "BODY_REMOVED";
  case Fate::Erased:
    return "ERASED";
  }
  return "LIVE";
}

Tracker::Tracker(Config C) : Cfg(std::move(C)) {
  std::error_code EC;
  Out = std::make_unique<raw_fd_ostream>(Cfg.OutPath, EC, sys::fs::OF_Text);
  if (EC)
    Out.reset();
}

Tracker::~Tracker() { finish(); }

void Tracker::handshake(const Module &M) {
  if (!Out)
    return;
  const std::string Id = M.getModuleIdentifier();
  if (Announced && Id == LastModuleId)
    return;
  Announced = true;
  LastModuleId = Id;
  *Out << "HANDSHAKE\t" << kSchema << "\t" << Id << "\t" << Cfg.TargetFn << "\t"
       << Cfg.ControlFn << "\t";
  for (size_t I = 0; I < Cfg.EffectSymbols.size(); ++I)
    *Out << (I ? "," : "") << Cfg.EffectSymbols[I];
  *Out << "\t" << modeName(Cfg.ObsMode) << "\t" << (Cfg.RequireLiveBranch ? 1 : 0)
       << "\n";
  Out->flush();
}

void Tracker::passRecord(uint64_t S, StringRef Phase, StringRef PassID,
                         StringRef UnitKind, StringRef UnitName) {
  PassesSeen++;
  if (!Out || Cfg.ObsMode == Mode::Standard)
    return;
  *Out << "PASS\t" << S << "\t" << Phase << "\t" << PassID << "\t" << UnitKind
       << "\t" << UnitName << "\n";
  Out->flush();
}

void Tracker::skipRecord(uint64_t S, StringRef Phase, StringRef PassID) {
  Skipped++;
  if (!Out)
    return;
  *Out << "SKIP\t" << S << "\t" << Phase << "\t" << PassID << "\n";
  Out->flush();
}

UnitRecord *Tracker::trackedUnit(StringRef Name, uint64_t S, StringRef PassID) {
  const std::string Key = Name.str();
  auto It = Units.find(Key);
  if (It != Units.end())
    return &It->second;

  const std::string Root = lineageRoot(Name);
  std::string Role;
  if (Root == Cfg.TargetFn)
    Role = "subject";
  else if (Root == Cfg.ControlFn)
    Role = "control";
  else
    return nullptr;

  UnitRecord U;
  U.Name = Key;
  U.Lineage = Root;
  U.Role = Role;
  U.Clone = (Key != Root);
  U.BornSeq = S;
  U.BornPass = PassID.str();
  Units.emplace(Key, std::move(U));
  UnitOrder.push_back(Key);

  bool KnownLineage = false;
  for (const std::string &L : LineageOrder)
    if (L == Root)
      KnownLineage = true;
  if (!KnownLineage)
    LineageOrder.push_back(Root);

  if (Out) {
    *Out << "UNIT\t" << S << "\t" << PassID << "\t" << Root << "\t" << Key
         << "\t" << (Key != Root ? "CLONE_BORN" : "BORN") << "\n";
    Out->flush();
  }
  return &Units.find(Key)->second;
}

void Tracker::setFate(UnitRecord &U, Fate F, uint64_t S, StringRef PassID) {
  if (U.UnitFate == F)
    return;
  U.UnitFate = F;
  U.FateSeq = S;
  U.FatePass = PassID.str();
  if (Out) {
    *Out << "UNIT\t" << S << "\t" << PassID << "\t" << U.Lineage << "\t"
         << U.Name << "\t" << (F == Fate::Live ? "REAPPEARED" : fateName(F))
         << "\n";
    Out->flush();
  }
  writeSummaryFile();
}

void Tracker::syncModule(uint64_t S, StringRef PassID, const Module &M,
                         bool Full) {
  if (!Out)
    return;

  // Discovery. Only a full walk can find a unit that did not exist at the last
  // census -- a clone the inliner or function specialisation just produced.
  if (Full) {
    handshake(M);
    for (const Function &F : M) {
      if (F.isDeclaration())
        continue;
      const std::string Root = lineageRoot(F.getName());
      if (Root != Cfg.TargetFn && Root != Cfg.ControlFn)
        continue;
      UnitRecord *U = trackedUnit(F.getName(), S, PassID);
      if (U) {
        U->HadBody = true;
        if (U->UnitFate != Fate::Live)
          setFate(*U, Fate::Live, S, PassID);
      }
    }
  }

  // Census. This is the part that makes a deleted function visible: its
  // callbacks stop arriving and nothing else would ever say so.
  for (const std::string &Name : UnitOrder) {
    UnitRecord &U = Units.find(Name)->second;
    const Function *F = M.getFunction(Name);
    if (!F) {
      setFate(U, Fate::Erased, S, PassID);
      continue;
    }
    if (F->isDeclaration()) {
      if (U.HadBody)
        setFate(U, Fate::BodyRemoved, S, PassID);
      continue;
    }
    U.HadBody = true;
    if (U.UnitFate != Fate::Live)
      setFate(U, Fate::Live, S, PassID);
  }
}

void Tracker::snapshot(uint64_t S, StringRef PassID, const Function &F,
                       unsigned Count) {
  if (Cfg.SnapshotDir.empty() || !Out)
    return;
  const std::string Path =
      Cfg.SnapshotDir + "/snap-" + std::to_string(SnapSeq++) + ".ll";
  std::error_code EC;
  raw_fd_ostream Snap(Path, EC, sys::fs::OF_Text);
  if (EC)
    return;
  F.print(Snap);
  // The control goes into the same file. A shared predicate refuses to judge
  // without a co-resident control, and weakening that here -- at the one place
  // the measurement actually happens -- would defeat the point of having it.
  if (const Function *C = F.getParent()->getFunction(Cfg.ControlFn)) {
    Snap << "\n";
    C->print(Snap);
  }
  *Out << "SNAP\t" << S << "\t" << PassID << "\t" << F.getName() << "\t"
       << Count << "\t" << Path << "\n";
  Out->flush();
}

void Tracker::observe(uint64_t S, StringRef Phase, StringRef PassID,
                      StringRef UnitKind, const Function &F) {
  if (!Out || F.isDeclaration())
    return;
  const std::string Root = lineageRoot(F.getName());
  if (Root != Cfg.TargetFn && Root != Cfg.ControlFn)
    return;

  handshake(*F.getParent());
  UnitRecord *UP = trackedUnit(F.getName(), S, PassID);
  if (!UP)
    return;
  UnitRecord &U = *UP;
  U.HadBody = true;

  const unsigned N = countEffect(F, Cfg.EffectSymbols, Cfg.RequireLiveBranch);
  const bool IsFnAfter = (Phase == "after" && UnitKind == "function");
  const long Idx = IsFnAfter ? static_cast<long>(U.FnAfterObs) : -1;

  const State Prev = U.Cur;
  State New;
  if (N > 0) {
    // Reintroduction is sticky until the next loss, so that a unit that lost
    // and regained the effect keeps saying so at the end of the pipeline rather
    // than reverting to a PRESENT that hides the episode.
    New = (Prev == State::Lost || Prev == State::Reintroduced)
              ? State::Reintroduced
              : State::Present;
  } else {
    New = (Prev == State::Present || Prev == State::Reintroduced ||
           Prev == State::Lost)
              ? State::Lost
              : State::Absent;
  }

  const bool Changed = (New != Prev);
  const bool CountChanged = (!U.HaveLastCount || N != U.LastCount);

  if (Changed && New == State::Lost) {
    U.EverLost = true;
    U.LossEpisodes++;
    if (!U.HaveFirstLoss) {
      U.HaveFirstLoss = true;
      U.FirstLossSeq = S;
      U.FirstLossPass = PassID.str();
      U.FirstLossPrevPass = U.LastPresentPass;
      U.FirstLossPrevAfterPass = U.LastAfterPass;
      U.FirstLossFnIdx = Idx;
    }
  }
  if (New == State::Present)
    U.EverPresent = true;
  if (Changed && New == State::Reintroduced) {
    U.EverPresent = true;
    U.EverReintroduced = true;
  }

  if (N > 0)
    U.LastPresentPass = PassID.str();

  U.Cur = New;
  U.LastCount = N;
  U.HaveLastCount = true;

  if (Changed)
    U.Hist.push_back(HistEntry{S, Phase.str(), PassID.str(), N, New});

  const bool Emit =
      (Cfg.ObsMode != Mode::Standard) || Changed || CountChanged;
  if (Emit) {
    EvRecords++;
    *Out << "EV\t" << S << "\t" << Phase << "\t" << PassID << "\t" << UnitKind
         << "\t" << U.Name << "\t" << U.Lineage << "\t" << U.Role << "\t" << N
         << "\t" << stateName(New) << "\t" << (Changed ? 1 : 0) << "\n";
    Out->flush();
  }

  if (Cfg.ObsMode == Mode::Forensic && U.Role == "subject" && CountChanged)
    snapshot(S, PassID, F, N);

  if (Phase == "after")
    U.LastAfterPass = PassID.str();
  if (IsFnAfter)
    U.FnAfterObs++;

  if (Changed)
    writeSummaryFile();
}

void Tracker::emitSummaryInto(raw_ostream &OS) const {
  for (const std::string &Name : UnitOrder) {
    const UnitRecord &U = Units.find(Name)->second;
    OS << "SUMMARY\t" << U.Name << "\t" << U.Lineage << "\t" << U.Role << "\t"
       << (U.Clone ? 1 : 0) << "\t"
       << (U.HaveFirstLoss ? std::to_string(U.FirstLossSeq) : std::string("-"))
       << "\t" << (U.HaveFirstLoss ? U.FirstLossPass : std::string("-")) << "\t"
       << (U.HaveFirstLoss
               ? (U.FirstLossPrevPass.empty() ? std::string("-")
                                              : U.FirstLossPrevPass)
               : std::string("-"))
       << "\t"
       << (U.HaveFirstLoss
               ? (U.FirstLossPrevAfterPass.empty() ? std::string("-")
                                                   : U.FirstLossPrevAfterPass)
               : std::string("-"))
       << "\t" << (U.HaveFirstLoss ? U.FirstLossFnIdx : -1) << "\t"
       << stateName(U.Cur) << "\t" << (U.EverPresent ? 1 : 0) << "\t"
       << (U.EverLost ? 1 : 0) << "\t" << (U.EverReintroduced ? 1 : 0) << "\t"
       << U.LossEpisodes << "\t" << fateName(U.UnitFate) << "\t"
       << (U.UnitFate == Fate::Live ? std::string("-")
                                    : std::to_string(U.FateSeq))
       << "\t"
       << (U.UnitFate == Fate::Live ? std::string("-") : U.FatePass) << "\t"
       << U.Hist.size() << "\n";
  }
  for (const std::string &Name : UnitOrder) {
    const UnitRecord &U = Units.find(Name)->second;
    for (size_t I = 0; I < U.Hist.size(); ++I) {
      const HistEntry &H = U.Hist[I];
      OS << "HIST\t" << U.Name << "\t" << I << "\t" << H.Seq << "\t" << H.Phase
         << "\t" << H.Pass << "\t" << H.Count << "\t" << stateName(H.St)
         << "\n";
    }
  }
  OS << "STATS\t" << PassesSeen << "\t" << EvRecords << "\t" << UnitOrder.size()
     << "\t" << LineageOrder.size() << "\t" << Skipped << "\t"
     << modeName(Cfg.ObsMode) << "\n";
}

void Tracker::writeSummaryFile() {
  if (Cfg.OutPath.empty())
    return;
  std::error_code EC;
  raw_fd_ostream S(Cfg.OutPath + ".summary.tsv", EC, sys::fs::OF_Text);
  if (EC)
    return;
  emitSummaryInto(S);
}

void Tracker::finish() {
  if (Finished)
    return;
  Finished = true;
  writeSummaryFile();
  if (!Out)
    return;
  emitSummaryInto(*Out);
  Out->flush();
}

} // namespace propobs
