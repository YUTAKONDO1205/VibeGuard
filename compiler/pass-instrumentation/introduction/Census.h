//===- Census.h - the introduction census and its state series ------------===//
//
// Part of the introduction observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// This is the mirror image of the property observer's History.h. The loss side
// asks when an effect that was PRESENT went away; this side asks when something
// that was ABSENT arrived. Three things are the same because they have to be,
// and one is different.
//
// THE SAME.
//
// 1. Attribution is a pair, (pass, IR unit), never a pass alone. LLVM's
//    pipeline nests module inside call-graph inside function inside loop, and a
//    function pass's callback fires once per function -- so on a module with
//    twelve functions, one function pass produces twelve callbacks and "the
//    seventh pass" is not a position anyone can point at. `InstCombinePass on
//    intro_pass_subject` is. Every introduction here carries both halves, and
//    the pair is what the summary is keyed by.
//
// 2. The series runs to the end of the pipeline and the whole of it is kept.
//    Something introduced by one pass can be removed by the next and rebuilt by
//    a third; a checker that stopped at the first arrival would report an
//    introduction that a later pass undid. interfaces.md §3 requires the whole
//    sequence, so the first introduction and the final state are recorded as
//    separate facts and never collapsed into one.
//
// 3. Nothing keeps a `Function *` or a `Module *` between callbacks. A pass may
//    delete the function it was handed. Everything here is kept by name.
//
// THE DIFFERENT ONE: WHAT `ABSENT` MEANS, AND WHY THERE IS NO SEVENTH STATE.
//
// interfaces.md §3 fixes six states, and INTRODUCED is not one of them. It is
// not missing: it is the name of a *transition*, ABSENT -> PRESENT, and the
// states either side of it already exist. The later arrivals have a state of
// their own -- REINTRODUCED -- because by then the element has a history. So
// this component records the transition as an INTRO record and the states as
// the vocabulary spells them, rather than inventing a word and quietly widening
// a contract that three other components are written against.
//
// The ABSENT entry is measured, not assumed. Every observation enumerates a
// whole scope, so when an element first appears in scope S at seq k, the
// previous observation of S at seq j is a point at which the scope was
// enumerated and this element was not in it. That is an observation of absence,
// and it is written with seq j -- the seq at which it was actually seen to be
// absent. An element already present at the very first observation of its scope
// gets no ABSENT entry and is marked `atEntry`, because there is no point at
// which this plugin saw the scope without it: the front end put it there, and
// blaming the first pass to run would be an attribution the measurement does
// not support.
//
// THE LOG. Line-oriented TSV; field one is the record type.
//
//   HANDSHAKE schema moduleId mode control watch
//   PASS      seq phase passID passUnitKind passUnitName
//   ELEM      seq phase passID passUnitKind passUnitName scope kind element
//             count state changed
//   INTRO     seq phase passID passUnitKind passUnitName scope kind element
//             atEntry prevAfterPass fnIdx
//   SUMMARY   scope kind element firstIntroSeq firstIntroPhase firstIntroPass
//             firstIntroUnitKind firstIntroUnit firstIntroPrevAfterPass
//             firstIntroFnIdx atEntry finalState everPresent everLost
//             everReintroduced introEpisodes lossEpisodes histLen
//   HIST      scope kind element idx seq phase passID count state repeats
//             lastSeq lastPass
//   SKIP      seq phase passID
//   STATS     passesSeen elemRecords elementsTracked scopes skipped mode
//             controlSeen controlFinalState
//
// `passUnitKind` is the kind of IR unit the *pass* ran on; `scope` is where the
// element lives, which is the module for a symbol and a function for a call
// site. They are different questions and conflating them loses the attribution.
//
//===----------------------------------------------------------------------===//

#ifndef INTRODUCTION_OBSERVER_CENSUS_H
#define INTRODUCTION_OBSERVER_CENSUS_H

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

namespace introobs {

/// interfaces.md §3, in full. NotApplicable is declared because the contract
/// declares it and is never emitted here: deciding that a question lost its
/// referent is a judgement about the property, and an observer that made it
/// would be deciding the answer it exists to measure.
enum class State {
  NotObserved,
  Present,
  Absent,
  Lost,
  Reintroduced,
  NotApplicable,
};

const char *stateName(State S);

enum class Kind { Symbol, ExternalCall, Initialiser, Section };
const char *kindName(Kind K);

/// One run of consecutive observations that agreed.
///
/// The contract (interfaces.md §3) is that the whole sequence is kept and that
/// nothing stops at the first transition. It is not that every observation gets
/// a line: on this component's own fixture the module scope is observed 690
/// times and the answer is the same every time, so a per-observation history
/// would be six hundred and ninety lines saying PRESENT. Runs of identical
/// (state, count) are therefore folded, and `Repeats` records how many
/// observations were folded into the entry, so nothing about how much was
/// looked at is lost either. Every state change and every count change starts a
/// new entry, which is what makes the *series* whole.
struct HistEntry {
  uint64_t Seq = 0;          ///< the observation at which this run began
  uint64_t LastSeq = 0;      ///< the last observation in the run
  std::string Phase;
  std::string Pass;
  std::string LastPass;      ///< the pass at the end of the run
  unsigned Count = 0;
  unsigned Repeats = 1;      ///< observations folded into this entry
  State St = State::NotObserved;
};

/// One element, in one scope, across the whole pipeline.
struct ElementRecord {
  std::string Scope;
  Kind ElemKind = Kind::Symbol;
  std::string Name;

  State Cur = State::NotObserved;
  bool EverPresent = false;
  bool EverLost = false;
  bool EverReintroduced = false;
  unsigned IntroEpisodes = 0;
  unsigned LossEpisodes = 0;

  /// The first ABSENT -> PRESENT transition: the introduction.
  bool HaveFirstIntro = false;
  uint64_t FirstIntroSeq = 0;
  std::string FirstIntroPhase;
  std::string FirstIntroPass;
  std::string FirstIntroUnitKind;
  std::string FirstIntroUnit;
  /// The pass of the previous `after` observation of this scope -- the pass
  /// that ran immediately before the one blamed. Read off the pipeline rather
  /// than off the element, which is what makes it move when the cause moves and
  /// is why a hard-coded answer cannot produce it.
  std::string FirstIntroPrevAfterPass;
  /// Position of the introduction in this scope's stream of (phase=after,
  /// passUnitKind=function) observations, zero-based; -1 when it was seen at a
  /// module, call-graph or loop boundary instead.
  long FirstIntroFnIdx = -1;
  /// True when the element was already there the first time its scope was
  /// looked at. No pass introduced it -- the front end did.
  bool AtEntry = false;

  std::vector<HistEntry> Hist;
};

/// Bookkeeping for one scope: the module, or one function.
struct ScopeRecord {
  std::string Name;
  uint64_t Observations = 0;
  uint64_t LastObsSeq = 0;
  std::string LastObsPhase;
  std::string LastObsPass;
  std::string LastAfterPass;
  unsigned FnAfterObs = 0;
};

/// One observation of one scope: the whole set of elements found in it, with
/// their counts. Counts, not names -- interfaces.md §4: two calls to the same
/// callee are two call sites, and the oracle is defined over the count.
using Observed = std::map<std::pair<Kind, std::string>, unsigned>;

class Census {
public:
  explicit Census(Config Cfg);
  ~Census();

  bool ok() const { return Out != nullptr; }
  uint64_t nextSeq() { return ++Seq; }

  void handshake(const llvm::Module &M);

  void passRecord(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID,
                  llvm::StringRef UnitKind, llvm::StringRef UnitName);
  void skipRecord(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID);

  /// Census the module scope: defined symbols, static initialisers, explicit
  /// sections. Cheap -- it walks symbol tables, never bodies.
  void syncModuleScope(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID,
                       llvm::StringRef UnitKind, llvm::StringRef UnitName,
                       const llvm::Module &M);

  /// Census one function scope: the external calls in its body.
  void syncFunctionScope(uint64_t S, llvm::StringRef Phase, llvm::StringRef PassID,
                         llvm::StringRef UnitKind, llvm::StringRef UnitName,
                         const llvm::Function &F);

  void finish();

  const Config &config() const { return Cfg; }

private:
  void applyScope(llvm::StringRef Scope, uint64_t S, llvm::StringRef Phase,
                  llvm::StringRef PassID, llvm::StringRef UnitKind,
                  llvm::StringRef UnitName, const Observed &Now);
  ScopeRecord &scopeFor(llvm::StringRef Name);
  void writeSummaryFile();
  void emitSummaryInto(llvm::raw_ostream &OS) const;

  Config Cfg;
  std::unique_ptr<llvm::raw_fd_ostream> Out;
  std::string LastModuleId;
  bool Announced = false;
  bool Finished = false;

  uint64_t Seq = 0;
  uint64_t PassesSeen = 0;
  uint64_t ElemRecords = 0;
  uint64_t Skipped = 0;

  std::map<std::string, ElementRecord> Elements;
  std::vector<std::string> ElementOrder;
  std::map<std::string, ScopeRecord> Scopes;
  std::vector<std::string> ScopeOrder;
};

} // namespace introobs

#endif // INTRODUCTION_OBSERVER_CENSUS_H
