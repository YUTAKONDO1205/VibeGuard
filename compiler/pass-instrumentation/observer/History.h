//===- History.h - per-unit state histories and the log they produce ------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// Three things here are deliberate and are the reason this is not just a
// counter.
//
// 1. Attribution is a pair, (pass, IR unit), never a pass alone. LLVM's
//    pipeline nests module inside call-graph inside function inside loop, and a
//    function pass's callback fires once per function. "The seventh pass" is
//    not a position anyone can point at; "DSEPass on handle_request" is.
//
// 2. The history runs to the end of the pipeline. A property can be removed in
//    one form and rebuilt in another -- a call replaced by inline stores that a
//    later pass turns back into a call -- and a checker that stops at the first
//    PRESENT -> LOST transition reports a loss that a later pass undid. Section
//    3 of compiler/schema/interfaces.md requires the whole sequence, and the
//    first loss and the final state are recorded as separate facts.
//
// 3. A unit can disappear. When a function is deleted its function-pass
//    callbacks simply stop arriving; nothing announces it. Left alone, the last
//    recorded state stays PRESENT for ever and the loss is never reported. So
//    the observer keeps its own census of the tracked units and records a
//    disappearance as a disappearance -- not as a loss of the property, because
//    those are different claims and merging them is how a checker starts lying.
//
// The log is line-oriented TSV. Field one is the record type:
//
//   HANDSHAKE schema moduleId target control effectSymbols mode reqLiveBranch
//   SUBJECTRES seq moduleId role name resolution          (resolved|
//                                                          declaration-only|
//                                                          not-in-module|
//                                                          not-scanned)
//   PASS      seq phase passID passUnitKind passUnitName  (trace/forensic)
//   EV        seq phase passID passUnitKind unit lineage role count state
//             changed
//   UNIT      seq passID lineage unit event               (BORN|CLONE_BORN|
//                                                          REAPPEARED|
//                                                          BODY_REMOVED|ERASED)
//
// `passUnitKind` is the kind of IR unit the *pass* ran on (module, cgscc,
// function, loop); `unit` is always the function the count was taken in, since
// that is the only unit the oracle is defined over.
//   SNAP      seq passID unit count path                    (forensic)
//   SKIP      seq phase passID                              (unsupported unit kind)
//   SUMMARY   unit lineage role clone firstLossSeq firstLossPass
//             firstLossPrevPass firstLossPrevAfterPass firstLossFnIdx
//             finalState everPresent everLost everReintroduced lossEpisodes
//             fate fateSeq fatePass histLen
//   HIST      unit idx seq phase passID count state
//   STATS     passesSeen evRecords unitsTracked lineages skipped mode
//
// SUMMARY and HIST are also written, on their own, to `<OBS_OUT>.summary.tsv`
// after every change, so that a run whose process does not unwind still leaves
// a current attribution behind.
//
// 4. A name that resolves to nothing is not an absence of the property.
//    `OBS_TARGET_FN` is a string, and a misspelt string produces a log in which
//    the control is PRESENT and the subject simply never appears -- the same
//    shape a genuine "the subject was erased before the first boundary" would
//    have, and one the co-resident control cannot distinguish, because the
//    control is fine. Whether the name resolves cannot be decided when the
//    plugin is loaded: `llvmGetPassPluginInfo` registers callbacks and there is
//    no module yet. It can only be decided the first time a module is walked,
//    which is where SUBJECTRES is written.
//
//    SUBJECTRES is a *fact about one module*, never a verdict about the run. In
//    a whole-project build the plugin is loaded for every translation unit, and
//    a subject that lives in one file is legitimately absent from all the
//    others; module-level evidence cannot tell that apart from a typo. The
//    verdict -- "no module in this run resolved the subject" -- belongs to
//    whatever reads the logs of the whole run, and lives in
//    lib/subject-resolution.mjs.
//
//===----------------------------------------------------------------------===//

#ifndef PROPERTY_OBSERVER_HISTORY_H
#define PROPERTY_OBSERVER_HISTORY_H

#include "Config.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace propobs {

/// The states of compiler/schema/interfaces.md section 3.
///
/// NotApplicable is declared because the contract declares it, and is never
/// emitted by this component: deciding that a question lost its referent is a
/// judgement about the property, and an observer that made it would be deciding
/// the answer it is supposed to be measuring. A driver that can make that
/// judgement makes it from the Forensic snapshots.
enum class State {
  NotObserved,
  Present,
  Absent,
  Lost,
  Reintroduced,
  NotApplicable,
};

const char *stateName(State S);

/// What happened to the IR unit itself, which is a different question from what
/// happened to the property inside it.
enum class Fate {
  Live,
  /// Still in the module, but the body is gone -- it is a declaration now.
  BodyRemoved,
  /// No longer in the module at all.
  Erased,
};

const char *fateName(Fate F);

struct HistEntry {
  uint64_t Seq = 0;
  std::string Phase;
  std::string Pass;
  unsigned Count = 0;
  State St = State::NotObserved;
};

/// One concrete IR unit: a function, under the name it has in the module.
///
/// Clones get their own record. That is what stops the false reintroduction:
/// `handle_request.llvm.1041` starting its own history at PRESENT is a birth,
/// not the return of something lost.
struct UnitRecord {
  std::string Name;
  std::string Lineage;
  std::string Role; // "subject" or "control"
  bool Clone = false;

  uint64_t BornSeq = 0;
  std::string BornPass;
  bool HadBody = false;

  Fate UnitFate = Fate::Live;
  uint64_t FateSeq = 0;
  std::string FatePass;

  State Cur = State::NotObserved;
  bool EverPresent = false;
  bool EverLost = false;
  bool EverReintroduced = false;

  bool HaveFirstLoss = false;
  uint64_t FirstLossSeq = 0;
  std::string FirstLossPass;
  /// The pass of the last observation at which the effect was still counted.
  /// Usually the losing pass itself, seen at its `before` boundary.
  std::string FirstLossPrevPass;
  /// The pass of the previous `after` observation of this unit -- that is, the
  /// pass that ran immediately before the one blamed. This is the field that
  /// shows an attribution moved when the cause moved: it is read off the
  /// pipeline, not off the property, so a hard-coded answer cannot produce it.
  std::string FirstLossPrevAfterPass;
  /// Position of the loss in this unit's stream of (phase=after,
  /// unitKind=function) observations, zero-based; -1 when the loss was seen at
  /// a module, call-graph or loop boundary instead.
  long FirstLossFnIdx = -1;

  unsigned LossEpisodes = 0;
  unsigned FnAfterObs = 0;
  std::string LastPresentPass;
  std::string LastAfterPass;

  bool HaveLastCount = false;
  unsigned LastCount = 0;

  std::vector<HistEntry> Hist;
};

/// Owns the log, the census and every unit's history.
///
/// Holds no `Function *` and no `Module *`. A pointer to IR is valid only for
/// the duration of the callback that handed it over; anything kept between
/// callbacks is kept by name.
class Tracker {
public:
  explicit Tracker(Config Cfg);
  ~Tracker();

  bool ok() const { return Out != nullptr; }

  uint64_t nextSeq() { return ++Seq; }

  void handshake(const llvm::Module &M);

  /// Write, once per module, whether `OBS_TARGET_FN` and `OBS_CONTROL_FN`
  /// resolve to a defined function in it.
  ///
  /// Called from the full census, which is the earliest point at which the
  /// question has an answer at all. Records a fact and refuses to draw the
  /// conclusion from it -- see note 4 at the top of this file.
  void resolution(uint64_t S, const llvm::Module &M);

  /// Record that a pass ran, whatever unit it ran on. Written in Trace and
  /// Forensic modes only.
  void passRecord(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID,
                  llvm::StringRef UnitKind, llvm::StringRef UnitName);

  /// Take the census. `Full` walks the whole module and discovers units that
  /// did not exist before; the cheap form only asks whether the units already
  /// known are still there, which is a symbol-table lookup each.
  void syncModule(uint64_t S, llvm::StringRef PassID, const llvm::Module &M,
                  bool Full);

  /// Observe one function at one boundary.
  void observe(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID,
               llvm::StringRef UnitKind, const llvm::Function &F);

  /// An IR unit kind this component does not count.
  void skipRecord(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID);

  /// Write SUMMARY, HIST and STATS into the main log. Idempotent.
  void finish();

  const Config &config() const { return Cfg; }

private:
  UnitRecord *trackedUnit(llvm::StringRef Name, uint64_t S,
                          llvm::StringRef PassID);
  void setFate(UnitRecord &U, Fate F, uint64_t S, llvm::StringRef PassID);
  void writeSummaryFile();
  void emitSummaryInto(llvm::raw_ostream &OS) const;
  void snapshot(uint64_t S, llvm::StringRef PassID, const llvm::Function &F,
                unsigned Count);

  Config Cfg;
  std::unique_ptr<llvm::raw_fd_ostream> Out;
  std::string LastModuleId;
  bool Announced = false;
  bool Finished = false;

  /// The module the last SUBJECTRES pair was written for, and whether any pair
  /// has been written at all. The second is what makes the "no module boundary
  /// was ever reached" case say so, instead of leaving the question unasked and
  /// unrecorded -- which is the failure this record exists to end.
  std::string ResolvedModuleId;
  bool ResolutionWritten = false;

  uint64_t Seq = 0;
  uint64_t PassesSeen = 0;
  uint64_t EvRecords = 0;
  uint64_t Skipped = 0;
  unsigned SnapSeq = 0;

  /// Concrete unit name -> its record. Insertion order is kept separately so
  /// that the summary is deterministic without depending on map ordering of
  /// names that a pass invented.
  std::map<std::string, UnitRecord> Units;
  std::vector<std::string> UnitOrder;
  std::vector<std::string> LineageOrder;
};

} // namespace propobs

#endif // PROPERTY_OBSERVER_HISTORY_H
