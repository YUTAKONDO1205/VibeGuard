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

#include <atomic>
#include <mutex>
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

Tracker::Tracker(Config C)
    : Cfg(std::move(C)),
      PreOpenOS(std::make_unique<raw_string_ostream>(PreOpen)) {}

Tracker::~Tracker() { finish(); }

raw_ostream &Tracker::out() {
  return LogSt == LogState::Open ? static_cast<raw_ostream &>(*Out)
                                 : static_cast<raw_ostream &>(*PreOpenOS);
}

/// A module identifier under ThinLTO is a whole object path, so it cannot be
/// dropped into a filename as it stands. Everything outside `[A-Za-z0-9._-]`
/// becomes `_`, which keeps the path's shape readable in a directory listing
/// while making the name one component.
///
/// `path::filename` would be shorter and is wrong: `a/x.o` and `b/x.o` are two
/// different backends and would choose the same log, which is the very
/// collision this whole change exists to remove.
///
/// NAME_MAX is 255 on Linux and the path is the build tree's, not ours, so a
/// deep enough tree would produce a name the filesystem refuses -- silently
/// turning into a failed open. Past 128 characters the tracker falls back to
/// its index instead. That name says nothing about the module, which is
/// precisely why the manifest records the path each tracker opened rather than
/// only its module id: a reader that cannot re-derive the name does not have
/// to.
static std::string sanitiseForFilename(StringRef Id, unsigned Index) {
  std::string S;
  S.reserve(Id.size());
  for (char C : Id) {
    const bool Keep = (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
                      (C >= '0' && C <= '9') || C == '.' || C == '_' ||
                      C == '-';
    S.push_back(Keep ? C : '_');
  }
  if (S.empty() || S.size() > 128)
    return "module-" + std::to_string(Index);
  return S;
}

/// The manifest lock, and the count of trackers that have reached a module
/// boundary in this process.
///
/// The count is claimed under the same lock as the manifest write, and that is
/// not belt-and-braces. The tracker holding index 0 is the one that keeps the
/// unsuffixed name and the one that truncates the manifest; if the index were
/// claimed lock-free and only the write were guarded, a later tracker could
/// reach the lock first, write its line, and have index 0 truncate the file
/// from under it. Claiming both together makes "index 0" and "first to the
/// manifest" the same tracker, which is what lets the manifest be truncated per
/// run instead of accumulating every run that reuses one `OBS_OUT`.
static std::mutex &manifestMutex() {
  static std::mutex M;
  return M;
}
static std::atomic<unsigned> &trackerOpenCount() {
  static std::atomic<unsigned> C{0};
  return C;
}

void Tracker::openFor(StringRef ModuleId) {
  if (LogSt != LogState::Pending)
    return;

  unsigned Index = 0;
  {
    std::lock_guard<std::mutex> G(manifestMutex());
    Index = trackerOpenCount().fetch_add(1);
    LogPath = Index == 0
                  ? Cfg.OutPath
                  : Cfg.OutPath + "." + sanitiseForFilename(ModuleId, Index) +
                        ".tsv";

    // Written before the open is attempted, on purpose. A manifest line with no
    // log beside it is exactly the signal the manifest exists to give -- "a
    // backend ran and its history is not here" -- and suppressing the line when
    // the open fails would hide the one case a reader most needs to see.
    std::error_code MEC;
    raw_fd_ostream Man(Cfg.OutPath + ".modules", MEC,
                       Index == 0 ? sys::fs::OF_Text
                                  : (sys::fs::OF_Append | sys::fs::OF_Text));
    if (!MEC)
      Man << ModuleId << "\t" << LogPath << "\n";
  }

  std::error_code EC;
  auto F = std::make_unique<raw_fd_ostream>(LogPath, EC, sys::fs::OF_Text);
  if (EC) {
    // Loud, for the reason `refusing to install` is loud: the alternative is an
    // empty log that a driver reads as "nothing was lost". Built into one string
    // and emitted with one `<<` because under ThinLTO several backend threads
    // share this stderr, and a diagnostic split across writes comes back spliced
    // mid-word -- which is what the baseline for this change actually looked
    // like.
    const std::string Msg =
        "property-observer: cannot open OBS_OUT (" + LogPath + ")\n";
    errs() << Msg;
    LogSt = LogState::Failed;
    PreOpen.clear();
    return;
  }

  Out = std::move(F);
  SummaryPath = LogPath + ".summary.tsv";
  LogSt = LogState::Open;
  // Ahead of whatever the caller is about to write, so that a record produced
  // before the first module boundary keeps its place in the file.
  if (!PreOpen.empty()) {
    *Out << PreOpen;
    PreOpen.clear();
  }
  Out->flush();
}

void Tracker::handshake(const Module &M) {
  if (!ok())
    return;
  const std::string Id = M.getModuleIdentifier();
  if (Announced && Id == LastModuleId)
    return;
  // The first module boundary is the first moment this tracker knows which
  // module it belongs to, and therefore the first moment it can choose a name
  // no other backend's tracker will also choose. The file is named for the
  // FIRST module seen here; a `PassBuilder` that walked two modules would keep
  // writing both into it, which is the pre-existing behaviour and not something
  // ThinLTO produces.
  openFor(Id);
  if (!ok())
    return;
  Announced = true;
  LastModuleId = Id;
  out() << "HANDSHAKE\t" << kSchema << "\t" << Id << "\t" << Cfg.TargetFn << "\t"
       << Cfg.ControlFn << "\t";
  for (size_t I = 0; I < Cfg.EffectSymbols.size(); ++I)
    out() << (I ? "," : "") << Cfg.EffectSymbols[I];
  out() << "\t" << modeName(Cfg.ObsMode) << "\t" << (Cfg.RequireLiveBranch ? 1 : 0)
       << "\n";
  out().flush();
}

/// The three answers a module can give about a configured name, plus the one
/// the log gives when no module was ever walked.
///
/// Deliberately four new words. The six state names (PRESENT, ABSENT, LOST,
/// REINTRODUCED, NOT_APPLICABLE, NOT_OBSERVED) are answers about the property;
/// these are answers about whether the question had a referent here at all, and
/// spending a state word on one of them would leave two different facts sharing
/// a name.
static const char *const kResolved = "resolved";
static const char *const kDeclarationOnly = "declaration-only";
static const char *const kNotInModule = "not-in-module";
static const char *const kNotScanned = "not-scanned";

void Tracker::resolution(uint64_t S, const Module &M) {
  if (!ok())
    return;
  const std::string Id = M.getModuleIdentifier();
  if (ResolutionWritten && Id == ResolvedModuleId)
    return;
  ResolutionWritten = true;
  ResolvedModuleId = Id;

  // The control is asked the same question as the subject. A control that does
  // not resolve breaks the measurement just as completely, and the existing
  // invariant -- "the control held, so the run was sound" -- is exactly the one
  // that cannot notice it.
  struct RoleSpec {
    const char *Role;
    const char *EnvVar;
    const std::string *Name;
  };
  const RoleSpec Roles[2] = {{"subject", "OBS_TARGET_FN", &Cfg.TargetFn},
                             {"control", "OBS_CONTROL_FN", &Cfg.ControlFn}};

  for (const RoleSpec &R : Roles) {
    // Lineage, not equality: at the first module boundary the name is the one
    // the frontend emitted, but a later module boundary can be reached after
    // the inliner has produced `handle_request.llvm.1041`. Asking for the exact
    // name there would report a subject that is plainly present as missing.
    const char *Res = kNotInModule;
    for (const Function &F : M) {
      if (lineageRoot(F.getName()) != *R.Name)
        continue;
      if (F.isDeclaration()) {
        // Keep looking: a declaration and a definition of the same lineage can
        // both be in the module, and the definition is the one that decides.
        Res = kDeclarationOnly;
        continue;
      }
      Res = kResolved;
      break;
    }

    out() << "SUBJECTRES\t" << S << "\t" << Id << "\t" << R.Role << "\t"
         << *R.Name << "\t" << Res << "\n";

    if (Res == kResolved)
      continue;
    // Loud, for the same reason `refusing to install` is loud -- and still not
    // an error, because this module alone cannot tell a misspelt name from a
    // subject that lives in a different translation unit, and failing a corpus
    // build on a fact that is routinely innocent would make the record useless
    // rather than trustworthy.
    //
    // Built into one string and emitted with one `<<`. Under ThinLTO several
    // backend threads write to this stderr at once, and this message used to go
    // out in eight separate writes: the result was two backends' diagnostics
    // spliced mid-word into text no reader could act on. The wording is
    // unchanged; only the number of writes is.
    const std::string Msg =
        std::string("property-observer: ") + R.Role + " name '" + *R.Name +
        "' (" + R.EnvVar + ") did not resolve to a defined function in module " +
        Id + "; recorded as " + Res +
        ". If no module in this run resolves it, this run observed nothing "
        "about the " +
        R.Role + " -- check the whole run, not this log alone.\n";
    errs() << Msg;
  }
  out().flush();
}

void Tracker::passRecord(uint64_t S, StringRef Phase, StringRef PassID,
                         StringRef UnitKind, StringRef UnitName) {
  PassesSeen++;
  if (!ok() || Cfg.ObsMode == Mode::Standard)
    return;
  out() << "PASS\t" << S << "\t" << Phase << "\t" << PassID << "\t" << UnitKind
       << "\t" << UnitName << "\n";
  out().flush();
}

void Tracker::skipRecord(uint64_t S, StringRef Phase, StringRef PassID) {
  Skipped++;
  if (!ok())
    return;
  out() << "SKIP\t" << S << "\t" << Phase << "\t" << PassID << "\n";
  out().flush();
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

  if (ok()) {
    out() << "UNIT\t" << S << "\t" << PassID << "\t" << Root << "\t" << Key
         << "\t" << (Key != Root ? "CLONE_BORN" : "BORN") << "\n";
    out().flush();
  }
  return &Units.find(Key)->second;
}

void Tracker::setFate(UnitRecord &U, Fate F, uint64_t S, StringRef PassID) {
  if (U.UnitFate == F)
    return;
  U.UnitFate = F;
  U.FateSeq = S;
  U.FatePass = PassID.str();
  if (ok()) {
    out() << "UNIT\t" << S << "\t" << PassID << "\t" << U.Lineage << "\t"
         << U.Name << "\t" << (F == Fate::Live ? "REAPPEARED" : fateName(F))
         << "\n";
    out().flush();
  }
  writeSummaryFile();
}

void Tracker::syncModule(uint64_t S, StringRef PassID, const Module &M,
                         bool Full) {
  if (!ok())
    return;

  // Discovery. Only a full walk can find a unit that did not exist at the last
  // census -- a clone the inliner or function specialisation just produced.
  if (Full) {
    handshake(M);
    // Before discovery, because the answer is about the module as the pipeline
    // handed it over, and because a reader should meet it next to the handshake
    // that says which names were asked for.
    resolution(S, M);
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
  if (Cfg.SnapshotDir.empty() || !ok())
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
  out() << "SNAP\t" << S << "\t" << PassID << "\t" << F.getName() << "\t"
       << Count << "\t" << Path << "\n";
  out().flush();
}

void Tracker::observe(uint64_t S, StringRef Phase, StringRef PassID,
                      StringRef UnitKind, const Function &F) {
  if (!ok() || F.isDeclaration())
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
    out() << "EV\t" << S << "\t" << Phase << "\t" << PassID << "\t" << UnitKind
         << "\t" << U.Name << "\t" << U.Lineage << "\t" << U.Role << "\t" << N
         << "\t" << stateName(New) << "\t" << (Changed ? 1 : 0) << "\n";
    out().flush();
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
  // Empty until the log is open, and never set when the open failed. The side
  // file follows the log it belongs to: writing one under the unsuffixed stem
  // while the history went to a suffixed log would put a second backend's
  // attribution where a reader expects the first one's -- the same confusion in
  // a smaller file, and the side file is the one this lane found people read.
  if (SummaryPath.empty())
    return;
  std::error_code EC;
  raw_fd_ostream S(SummaryPath, EC, sys::fs::OF_Text);
  if (EC)
    return;
  emitSummaryInto(S);
}

void Tracker::finish() {
  if (Finished)
    return;
  Finished = true;
  // A tracker that never reached a module boundary has no file yet, and the
  // records below -- SUBJECTRES not-scanned, the summary, STATS -- are exactly
  // the ones that say so. Before this change the eager constructor had already
  // created the file, and an empty log is a fact ("this process ran the plugin
  // and observed nothing") that a missing log cannot state. Opening here, with
  // no module id to name it after, is what keeps that fact on disk.
  if (LogSt == LogState::Pending)
    openFor("");
  writeSummaryFile();
  if (!ok())
    return;
  // No full module census ever ran -- an `opt` pipeline with no module-level
  // pass in it, or a compilation that ended before the first one. The names may
  // be perfect and they were never put to a module, so the log says that rather
  // than staying silent and letting a reader assume either answer.
  if (!ResolutionWritten) {
    ResolutionWritten = true;
    out() << "SUBJECTRES\t0\t-\tsubject\t" << Cfg.TargetFn << "\t" << kNotScanned
         << "\n"
         << "SUBJECTRES\t0\t-\tcontrol\t" << Cfg.ControlFn << "\t"
         << kNotScanned << "\n";
    // One write, for the reason given in `resolution` above.
    const std::string Msg =
        "property-observer: no module boundary was reached, so whether "
        "OBS_TARGET_FN='" +
        Cfg.TargetFn + "' resolves to anything was never determined; recorded "
                       "as " +
        kNotScanned + "\n";
    errs() << Msg;
  }
  emitSummaryInto(out());
  out().flush();
}

} // namespace propobs
