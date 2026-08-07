// IrCheckpoints -- the pre-optimisation and post-optimisation observers.
//
// Two checkpoints, one question: was the effect a declared security property
// depends on still there at the end of the optimiser, and if it was not, which
// of the two very different reasons applies.
//
//   LOST            the effect is gone and the thing it acted on is still here.
//   NOT_APPLICABLE  the representation changed, so the question no longer has
//                   the same referent -- the buffer was promoted out of memory,
//                   or the unit was inlined away and deleted.
//
// Collapsing those two into one verdict is how this kind of checker turns into
// a false-positive generator: at -O2 a great many buffers stop being buffers,
// and reporting each of them as a removed wipe would bury the one case where a
// wipe really was deleted. So the decision below is made from a structural fact
// about the object the effect acted on, not from the effect count alone -- the
// count trajectory is identical (1 -> 0) in both fixtures that demonstrate it.
//
// Configuration is by environment variable, with the names fixed in
// compiler/schema/interfaces.md section 0:
//
//   OBS_TARGET_FN            subject IR unit (required)
//   OBS_CONTROL_FN           control IR unit, whose effect cannot be removed (required)
//   OBS_EFFECT_SYMBOLS       comma separated (required)
//   OBS_OUT                  record path (required)
//   OBS_SNAPSHOT_DIR         where to drop IR at each count change (optional)
//   OBS_REQUIRE_LIVE_BRANCH  1 to demand a live conditional branch (optional)
//
// and four names this component needed that interfaces.md does not yet list.
// They are reported rather than added there unilaterally:
//
//   OBS_EXTRACTOR            ir.wipe-effect | ir.guarded-call | ir.forbidden-callee
//   OBS_FORBIDDEN_SYMBOLS    comma separated, for ir.forbidden-callee
//   OBS_PROPERTY_ID          id from compiler/schema/properties.json
//   OBS_FIXTURE_REL          source path relative to the fixture root
//
// and one that exists only to be a positive control -- it switches off the
// discriminator this file is about, so that a fixture which should read
// NOT_APPLICABLE can be shown to read LOST when the discriminator is removed:
//
//   OBS_DISABLE_MEMOBJ_DISCRIMINATOR

#include "Extractors.h"
#include "Record.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;

namespace {

using irck::Extractor;
using irck::ExtractorConfig;
using irck::Json;
using irck::UnitFacts;

// ---------------------------------------------------------------- configuration

std::string envOr(const char *Name, const char *Default) {
  const char *V = std::getenv(Name);
  return V ? std::string(V) : std::string(Default);
}

std::vector<std::string> splitCommas(const std::string &S) {
  std::vector<std::string> Out;
  std::string Cur;
  for (char C : S) {
    if (C == ',') {
      if (!Cur.empty()) Out.push_back(Cur);
      Cur.clear();
    } else {
      Cur.push_back(C);
    }
  }
  if (!Cur.empty()) Out.push_back(Cur);
  return Out;
}

struct Config {
  std::string TargetFn;
  std::string ControlFn;
  std::string OutPath;
  std::string SnapshotDir;
  std::string PropertyId;
  std::string FixtureRel;
  ExtractorConfig Ext;
  Extractor Which = Extractor::WipeEffect;
  bool RequireLiveBranch = false;
  bool DisableMemObjDiscriminator = false;
  bool Valid = false;
};

Config loadConfig() {
  Config C;
  C.TargetFn = envOr("OBS_TARGET_FN", "");
  C.ControlFn = envOr("OBS_CONTROL_FN", "");
  C.Ext.EffectSymbols = splitCommas(envOr("OBS_EFFECT_SYMBOLS", ""));
  C.Ext.ForbiddenSymbols = splitCommas(envOr("OBS_FORBIDDEN_SYMBOLS", ""));
  C.OutPath = envOr("OBS_OUT", "");
  C.SnapshotDir = envOr("OBS_SNAPSHOT_DIR", "");
  C.PropertyId = envOr("OBS_PROPERTY_ID", "unnamed");
  C.FixtureRel = envOr("OBS_FIXTURE_REL", "");
  C.RequireLiveBranch = envOr("OBS_REQUIRE_LIVE_BRANCH", "0") == "1";
  C.DisableMemObjDiscriminator =
      envOr("OBS_DISABLE_MEMOBJ_DISCRIMINATOR", "0") == "1";

  std::string ExtName = envOr("OBS_EXTRACTOR", "ir.wipe-effect");
  if (!irck::parseExtractor(ExtName, C.Which)) return C;

  const bool NeedsEffect = C.Which != Extractor::ForbiddenCallee;
  const bool HaveSymbols = NeedsEffect ? !C.Ext.EffectSymbols.empty()
                                       : !C.Ext.ForbiddenSymbols.empty();
  C.Valid = !C.TargetFn.empty() && !C.ControlFn.empty() && HaveSymbols &&
            !C.OutPath.empty();
  return C;
}

// ----------------------------------------------------------------- property state

enum class State { Present, Absent, Lost, Reintroduced, NotApplicable, NotObserved };

const char *stateName(State S) {
  switch (S) {
  case State::Present: return "PRESENT";
  case State::Absent: return "ABSENT";
  case State::Lost: return "LOST";
  case State::Reintroduced: return "REINTRODUCED";
  case State::NotApplicable: return "NOT_APPLICABLE";
  case State::NotObserved: return "NOT_OBSERVED";
  }
  return "NOT_OBSERVED";
}

struct Verdict {
  State S = State::NotObserved;
  std::string Reason;
};

/// Did the object the effect acted on survive to the second checkpoint?
///
/// Asking "is an object of this size still here" was measured to be wrong in
/// the direction that matters: put a second 16-byte object in the same function
/// as the subject's 16-byte token, let it escape so it survives, and the subject
/// can be promoted entirely to SSA while the verdict still reads "the object it
/// acted on is still in memory" -- a removed wipe reported against a program
/// with no buffer left to wipe.
///
/// Names would settle it, and they are not there: clang discards value names
/// unless it is emitting IR, so at -O2 every alloca in the module is anonymous.
/// What survives that is the *census*. If the unit held two 16-byte objects
/// before and holds one after, a 16-byte object left, whatever it was called.
///
/// Returns true when an object of this size is still accounted for -- that is,
/// when the count of that size did not fall.
bool sizeCensusHeld(int64_t Size, const std::vector<int64_t> &Pre,
                    const std::vector<int64_t> &Post) {
  int64_t Before = 0, After = 0;
  for (int64_t V : Pre) if (V == Size) Before++;
  for (int64_t V : Post) if (V == Size) After++;
  return After >= Before;
}

/// Names are absent in an ordinary compile, but present when the caller asked
/// for them. When they are, they decide, because a census can be fooled by a
/// pass that creates a same-sized object while the subject's is promoted.
bool namedObjectSurvives(const irck::EffectTarget &Wanted,
                         const std::vector<std::pair<std::string, int64_t>> &Have) {
  for (const auto &H : Have)
    if (H.first == Wanted.Name) return true;
  return false;
}

/// The whole point of this file.
///
/// Reached only with the pre-optimisation and post-optimisation readings of the
/// *same* IR unit under the *same* extractor.
/// `InheritedPost` is the module's effect-call-site count at the second
/// checkpoint with the control's own contribution removed -- what the subject's
/// effect would have to be hiding in if it survived being inlined. It is only
/// consulted when the subject unit is gone; `HaveModuleCounts` says whether it
/// was measurable at all, because an unmeasured count must not read as zero.
Verdict decide(const UnitFacts &Pre, const UnitFacts &Post, const Config &C,
               bool SawZeroThenNonZero, int64_t InheritedPost,
               bool HaveModuleCounts) {
  Verdict V;

  if (!Pre.UnitPresent) {
    V.S = State::NotObserved;
    V.Reason = "subject unit was not present at the pre-optimisation checkpoint";
    return V;
  }

  // A unit that is gone at the second checkpoint may have had its effect carried
  // into whatever inlined it -- or may have had the effect deleted on the way.
  // Those are opposite answers, and unit presence alone cannot tell them apart.
  //
  // Deciding NOT_APPLICABLE from `!Post.UnitPresent` alone was measured to
  // report a wipe that the generated code does not perform: take the inlined
  // fixture, spell the wipe with a removable symbol, and at -O2 the callee is
  // inlined, the store is dead, and `entry` zeroes nothing -- while the verdict
  // read NOT_APPLICABLE with no findings and the same reason string as the
  // benign case. That is the failure interfaces.md section 3 names: a state
  // that means "the question changed" standing in for one that means "the
  // answer is no".
  //
  // What can be said comes from the effect sites still in the module that are
  // not the control's. If they account for what the subject contributed, the
  // effect went with the body. If there are none at all, it did not. In
  // between, this checkpoint pair does not carry enough to attribute -- and
  // saying so is the third answer, not a rounding of the other two.
  if (!Post.UnitPresent) {
    const int64_t SubjectPre = Pre.effect(C.Which);
    if (!HaveModuleCounts) {
      V.S = State::NotObserved;
      V.Reason = "unit-absent: the subject function is no longer a definition, and "
                 "no module-wide count was available to say whether its effect "
                 "went with it";
      return V;
    }
    if (InheritedPost >= SubjectPre) {
      V.S = State::NotApplicable;
      V.Reason = "unit-absent-effect-carried: the subject function is no longer a "
                 "definition (inlined and deleted), and the module still holds at "
                 "least as many effect sites outside the control as the subject "
                 "contributed";
      return V;
    }
    if (InheritedPost == 0 && SubjectPre > 0) {
      V.S = State::Lost;
      V.Reason = "unit-absent-effect-gone: the subject function was inlined away "
                 "and no effect site outside the control survives -- the effect "
                 "left the program with the body, rather than moving with it";
      return V;
    }
    V.S = State::NotObserved;
    V.Reason = "unit-absent-partially-accounted: the subject function is no longer "
               "a definition and the surviving effect sites outside the control do "
               "not account for what it contributed; this checkpoint pair cannot "
               "attribute the difference";
    return V;
  }

  const int64_t PreE = Pre.effect(C.Which);
  const int64_t PostE = Post.effect(C.Which);

  if (PreE == 0) {
    if (PostE > 0) {
      V.S = State::Present;
      V.Reason = "effect first appears after the pre-optimisation checkpoint";
    } else {
      V.S = State::Absent;
      V.Reason = "effect was never established at the pre-optimisation checkpoint";
    }
    return V;
  }

  if (PostE > 0) {
    V.S = SawZeroThenNonZero ? State::Reintroduced : State::Present;
    V.Reason = SawZeroThenNonZero
                   ? "effect count returned above zero after reaching zero "
                     "mid-pipeline; the whole sequence is in passHistory"
                   : "effect still counted at the post-optimisation checkpoint";
    return V;
  }

  // PreE > 0 and PostE == 0. This is the branch that decides whether a build
  // gets a finding or a shrug, and the count alone cannot decide it.
  if (!C.DisableMemObjDiscriminator) {
    std::vector<irck::EffectTarget> AllocaTargets;
    bool AllNamed = true;
    for (const irck::EffectTarget &T : Pre.Targets) {
      if (T.Kind != irck::TargetKind::Alloca) continue;
      AllocaTargets.push_back(T);
      if (T.Name.empty()) AllNamed = false;
    }

    if (!AllocaTargets.empty()) {
      bool AnySurvives = false;
      bool Decidable = false;
      for (const irck::EffectTarget &T : AllocaTargets) {
        if (AllNamed) {
          Decidable = true;
          if (namedObjectSurvives(T, Post.AllocaObjects)) { AnySurvives = true; break; }
        } else if (T.SizeBytes >= 0) {
          Decidable = true;
          if (sizeCensusHeld(T.SizeBytes, Pre.AllocaSizes, Post.AllocaSizes)) {
            AnySurvives = true;
            break;
          }
        }
      }

      if (!Decidable) {
        // No names and no statically known size. The only thing left that
        // settles it is that nothing survives at all.
        if (Pre.AllocaCount > 0 && Post.AllocaCount == 0) {
          V.S = State::NotApplicable;
          V.Reason = "memory-object-promoted: the object could not be identified "
                     "by name or size, but no stack object survives in the unit "
                     "at all";
        } else {
          V.S = State::NotObserved;
          V.Reason = "object-identity-unavailable: the effect's target has neither "
                     "a name nor a statically known size at this checkpoint, so "
                     "whether it was promoted cannot be decided here";
        }
        return V;
      }

      if (!AnySurvives) {
        V.S = State::NotApplicable;
        V.Reason = AllNamed
            ? "memory-object-promoted: the object the effect acted on is not "
              "among the objects still allocated in the unit, so 'was the "
              "buffer cleared' no longer has the same referent"
            : "memory-object-promoted: one fewer object of the effect target's "
              "size is allocated in the unit than before, so the object it acted "
              "on left memory and 'was the buffer cleared' no longer has the "
              "same referent";
        return V;
      }
    }
  }

  V.S = State::Lost;
  if (C.DisableMemObjDiscriminator) {
    V.Reason = "effect removed; the memory-object discriminator was switched "
               "off by OBS_DISABLE_MEMOBJ_DISCRIMINATOR, so this verdict is "
               "the one a checker without it would reach (positive control)";
  } else if (C.Which == Extractor::GuardedCall) {
    V.Reason = "guarded call removed and no conditional branch in the unit "
               "still tests a value: the check was decided at compile time "
               "rather than represented differently";
  } else {
    V.Reason = "effect removed while the object it acted on is still in memory "
               "at the post-optimisation checkpoint";
  }
  return V;
}

// ------------------------------------------------------------------- observation

struct Transition {
  std::string Pass;
  std::string Unit;
  std::string Role;
  int64_t From = 0;
  int64_t To = 0;
};

class Session {
public:
  explicit Session(Config Cfg) : C(std::move(Cfg)) {}

  const Config &cfg() const { return C; }

  /// pre-opt-ir checkpoint.
  void recordPreOpt(Module &M) {
    if (SawPre) return;
    SawPre = true;
    ModuleName = sys::path::filename(M.getModuleIdentifier()).str();
    if (const Function *F = M.getFunction(C.TargetFn)) Pre = irck::collectFacts(*F, C.Ext);
    if (const Function *F = M.getFunction(C.ControlFn)) PreCtl = irck::collectFacts(*F, C.Ext);
    NaivePre = irck::naiveModuleSymbolPresent(M, effectiveSymbols());
    ModuleCallsPre = irck::moduleWideCallSites(M, effectiveSymbols());
    seedHistory();
    snapshot(M, "pre-opt-ir");
  }

  /// Runs once per after-pass callback, before the per-unit reading, and does
  /// only what the naive oracle would do: ask the module whether the symbol is
  /// there. Recording it pass by pass is what makes the two oracles' answers
  /// comparable -- they are then two attributions from one run, rather than two
  /// runs that might have differed for some other reason.
  void noteModule(StringRef PassID, const Module &M) {
    if (!SawPre) return;
    ObsSeq++;
    const bool Present = irck::naiveModuleSymbolPresent(M, effectiveSymbols());
    if (NaiveWasPresent && !Present && FamilyAbsencePass.empty()) {
      FamilyAbsencePass = PassID.str();
      FamilyAbsenceSeq = ObsSeq;
    }
    NaiveWasPresent = Present;

    // Once the call has left the unit, watch the declaration it left behind.
    // The pass that finally removes that declaration is the pass a name-based
    // oracle would name as the cause -- and it is not the pass that removed the
    // call. Both are recorded, from the same run, so the disagreement is a
    // measurement.
    if (!ResidueWatch.empty() && ResidueSweptPass.empty()) {
      bool AnyLeft = false;
      for (const std::string &S : ResidueWatch)
        if (M.getFunction(S)) { AnyLeft = true; break; }
      if (!AnyLeft) {
        ResidueSweptPass = PassID.str();
        ResidueSweptSeq = ObsSeq;
      }
    }
  }

  /// after-pass checkpoint, for attribution only. The verdict is never taken
  /// from here: interfaces.md section 3 forbids stopping at the first
  /// PRESENT -> LOST transition, so this keeps every transition and the
  /// post-optimisation reading decides.
  void recordAfterPass(StringRef PassID, const Function &F) {
    if (!SawPre) return;
    const bool IsTarget = F.getName() == C.TargetFn;
    const bool IsControl = F.getName() == C.ControlFn;
    if (!IsTarget && !IsControl) return;

    UnitFacts U = irck::collectFacts(F, C.Ext);
    const int64_t N = U.effect(C.Which);
    int64_t &Last = IsTarget ? LastTarget : LastControl;
    bool &Have = IsTarget ? HaveTarget : HaveControl;

    if (IsControl) {
      if (!HaveCtlMin || N < CtlMin) { CtlMin = N; HaveCtlMin = true; }
    }
    if (IsTarget) {
      if (Have && Last > 0 && N == 0) SawZero = true;
      if (SawZero && N > 0) SawZeroThenNonZero = true;
    }

    if (!Have) { Have = true; Last = N; return; }
    if (N == Last) return;

    History.push_back(Transition{PassID.str(), F.getName().str(),
                                 IsTarget ? "subject" : "control", Last, N});
    Last = N;

    if (IsTarget && N == 0 && !HaveZeroPoint) {
      // The moment the effect left this unit: what the module looked like right
      // then is the only place the residue is visible, because a later pass
      // sweeps the declaration and takes the evidence with it.
      HaveZeroPoint = true;
      ZeroSeq = ObsSeq;
      NaiveAtZero = irck::naiveModuleSymbolPresent(*F.getParent(), effectiveSymbols());
      ModuleCallsAtZero =
          irck::moduleWideCallSites(*F.getParent(), effectiveSymbols());
      ResidueAtZero =
          irck::declaredButUncalledSymbols(*F.getParent(), effectiveSymbols());
      ResidueWatch = ResidueAtZero;
    }

    if (IsTarget) snapshotFunction(F, PassID, N);
  }

  /// post-optimisation checkpoint. Writes the record.
  void recordPostOptAndEmit(Module &M) {
    if (!SawPre || Emitted) return;
    Emitted = true;
    if (const Function *F = M.getFunction(C.TargetFn)) Post = irck::collectFacts(*F, C.Ext);
    if (const Function *F = M.getFunction(C.ControlFn)) PostCtl = irck::collectFacts(*F, C.Ext);
    NaivePost = irck::naiveModuleSymbolPresent(M, effectiveSymbols());
    ModuleCallsPost = irck::moduleWideCallSites(M, effectiveSymbols());
    ResiduePost = irck::declaredButUncalledSymbols(M, effectiveSymbols());
    snapshot(M, "post-opt-ir");
    snapshotModule(M, "post-opt-module");
    emit();
  }

private:
  const std::vector<std::string> &effectiveSymbols() const {
    return C.Which == Extractor::ForbiddenCallee ? C.Ext.ForbiddenSymbols
                                                 : C.Ext.EffectSymbols;
  }

  void seedHistory() {
    NaiveWasPresent = NaivePre;
    if (Pre.UnitPresent) { HaveTarget = true; LastTarget = Pre.effect(C.Which); }
    if (PreCtl.UnitPresent) {
      HaveControl = true;
      LastControl = PreCtl.effect(C.Which);
      CtlMin = LastControl;
      HaveCtlMin = true;
    }
  }

  void snapshot(Module &M, StringRef Tag) {
    if (C.SnapshotDir.empty()) return;
    std::error_code EC;
    raw_fd_ostream Out(C.SnapshotDir + "/" + Tag.str() + ".ll", EC, sys::fs::OF_Text);
    if (EC) return;
    if (const Function *F = M.getFunction(C.TargetFn)) F->print(Out);
    if (const Function *F = M.getFunction(C.ControlFn)) { Out << "\n"; F->print(Out); }
  }

  void snapshotModule(Module &M, StringRef Tag) {
    if (C.SnapshotDir.empty()) return;
    std::error_code EC;
    raw_fd_ostream Out(C.SnapshotDir + "/" + Tag.str() + ".ll", EC, sys::fs::OF_Text);
    if (EC) return;
    M.print(Out, nullptr);
  }

  void snapshotFunction(const Function &F, StringRef PassID, int64_t N) {
    if (C.SnapshotDir.empty()) return;
    std::error_code EC;
    std::string Path = C.SnapshotDir + "/change-" + std::to_string(SnapSeq++) + "-" +
                       PassID.str() + ".ll";
    raw_fd_ostream Out(Path, EC, sys::fs::OF_Text);
    if (EC) return;
    Out << "; effect count now " << N << " after " << PassID << "\n";
    F.print(Out);
    // The control travels in the same snapshot: a subject read without its
    // control next to it is not a measurement anybody should be able to quote.
    if (const Function *Ctl = F.getParent()->getFunction(C.ControlFn)) {
      Out << "\n";
      Ctl->print(Out);
    }
  }

  Json toolchainJson() const {
    Json Pkgs = Json::array();
    Json P = Json::object();
    P.set("name", Json::str("llvm"));
    P.set("version", Json::str(LLVM_VERSION_STRING));
    Pkgs.push(std::move(P));
    Json T = Json::object();
    T.set("clang", Json::str(LLVM_VERSION_STRING));
    T.set("packages", std::move(Pkgs));
    Json ForDigest = Json::object();
    ForDigest.set("clang", Json::str(LLVM_VERSION_STRING));
    ForDigest.set("packages", Json::array().push(Json::object()
                                                     .set("name", Json::str("llvm"))
                                                     .set("version", Json::str(LLVM_VERSION_STRING))));
    T.set("digest", Json::str(irck::sha256Hex(ForDigest.serialise())));
    return T;
  }

  void emit() {
    const bool SubjectIsControlToo = C.TargetFn == C.ControlFn;
    // The control's own sites are subtracted before the subject's effect is
    // looked for elsewhere in the module: leaving them in would let a control
    // that by construction cannot be optimised away vouch for a subject that
    // was.
    const int64_t InheritedPost =
        ModuleCallsPost - (PostCtl.UnitPresent && !SubjectIsControlToo
                               ? PostCtl.effect(C.Which)
                               : 0);
    Verdict V = decide(Pre, Post, C, SawZeroThenNonZero,
                       InheritedPost < 0 ? 0 : InheritedPost, true);

    const int64_t CtlPre = PreCtl.effect(C.Which);
    const int64_t CtlPost = PostCtl.effect(C.Which);
    const int64_t CtlFloor = HaveCtlMin ? CtlMin : CtlPost;
    // interfaces.md section 4: a run in which the control's count also reached
    // zero is a broken measurement, not a finding. This is recorded as a fact
    // in the record rather than left for a reader to notice.
    const bool ControlHeld = PreCtl.UnitPresent && PostCtl.UnitPresent &&
                             CtlPre > 0 && CtlPost > 0 && CtlFloor > 0 &&
                             !SubjectIsControlToo;

    Json R = Json::object();
    R.set("schemaVersion", Json::str("ir-checkpoints-v0"));
    R.set("component", Json::str("IrCheckpoints"));
    R.set("propertyId", Json::str(C.PropertyId));
    R.set("extractor", Json::str(irck::extractorName(C.Which)));
    R.set("source", Json::str(C.FixtureRel));
    R.set("module", Json::str(ModuleName));
    R.set("subjectUnit", Json::str(C.TargetFn));
    R.set("controlUnit", Json::str(C.ControlFn));
    R.set("toolchain", toolchainJson());

    Json Sym = Json::array();
    for (const std::string &S : effectiveSymbols()) Sym.push(Json::str(S));

    Json Or = Json::object();
    Or.set("counts", Json::str(C.Which == Extractor::ForbiddenCallee
                                   ? "call sites to a forbidden callee, resolved "
                                     "from the call instruction"
                                   : "call sites to an effect symbol, resolved "
                                     "from the call instruction, plus inline "
                                     "zero stores into a stack object or "
                                     "pointer parameter"));
    Or.set("unitOfCount", Json::str("one IR function"));
    Or.set("symbols", std::move(Sym));
    Or.set("requiresLiveBranch",
           Json::boolean(C.Which == Extractor::GuardedCall || C.RequireLiveBranch));
    Or.set("findingWhenPresent",
           Json::boolean(C.Which == Extractor::ForbiddenCallee));
    R.set("oracle", std::move(Or));

    Json CP = Json::object();
    CP.set("preOptIr", Pre.toJson(C.Which));
    CP.set("postOptIr", Post.toJson(C.Which));
    R.set("subject", std::move(CP));

    Json CC = Json::object();
    CC.set("preOptIr", PreCtl.toJson(C.Which));
    CC.set("postOptIr", PostCtl.toJson(C.Which));
    CC.set("minEffectObserved", Json::integer(CtlFloor));
    CC.set("held", Json::boolean(ControlHeld));
    R.set("control", std::move(CC));

    // The naive oracle's answer, recorded so the disagreement is a datum in the
    // record rather than a claim in a commit message.
    Json NO = Json::object();
    NO.set("method", Json::str("module symbol table lookup for the effect symbol"));
    NO.set("preOptSaysPresent", Json::boolean(NaivePre));
    NO.set("postOptSaysPresent", Json::boolean(NaivePost));
    NO.set("disagreesWithCallSiteOracle",
           Json::boolean(NaivePost && Post.effect(C.Which) == 0));
    NO.set("moduleWideCallSitesPreOpt", Json::integer(ModuleCallsPre));
    NO.set("moduleWideCallSitesPostOpt", Json::integer(ModuleCallsPost));
    NO.set("effectSitesOutsideControlPostOpt", Json::integer(InheritedPost < 0 ? 0 : InheritedPost));
    NO.set("declarationOnlyResidue",
           Json::boolean(NaivePost && ModuleCallsPost == 0));
    Json Res = Json::array();
    for (const std::string &S : ResiduePost) Res.push(Json::str(S));
    NO.set("declaredButUncalledSymbolsPostOpt", std::move(Res));
    R.set("naiveOracle", std::move(NO));

    Json H = Json::array();
    for (const Transition &T : History) {
      Json E = Json::object();
      E.set("pass", Json::str(T.Pass));
      E.set("unit", Json::str(T.Unit));
      E.set("role", Json::str(T.Role));
      E.set("from", Json::integer(T.From));
      E.set("to", Json::integer(T.To));
      H.push(std::move(E));
    }
    R.set("passHistory", std::move(H));

    Json FL = Json::object();
    bool FoundLoss = false;
    for (const Transition &T : History) {
      if (T.Role != "subject" || T.To != 0 || T.From <= 0) continue;
      FL.set("pass", Json::str(T.Pass));
      FL.set("unit", Json::str(T.Unit));
      FL.set("from", Json::integer(T.From));
      FoundLoss = true;
      break;
    }
    if (!FoundLoss) {
      FL.set("pass", Json::null());
      FL.set("unit", Json::null());
      FL.set("from", Json::null());
    }
    FL.set("note",
           Json::str(FoundLoss
                         ? "first transition of the subject's count to zero; "
                           "later transitions are in passHistory and were not "
                           "truncated"
                         : "the subject's count never reached zero at an "
                           "after-pass observation"));
    R.set("firstZeroTransition", std::move(FL));

    // Two oracles, one run, two attributions. interfaces.md section 4 says a
    // name search keeps reporting the effect as present until an unrelated pass
    // sweeps the leftover declaration, which then takes the blame; this is that
    // claim as a pair of numbers rather than as a sentence.
    Json OD = Json::object();
    Json CS = Json::object();
    CS.set("pass", FoundLoss ? Json::str(firstLossPass()) : Json::null());
    CS.set("observationIndex", HaveZeroPoint ? Json::integer(ZeroSeq) : Json::null());
    OD.set("callSiteOracle", std::move(CS));

    Json NN = Json::object();
    Json Watch = Json::array();
    for (const std::string &S : ResidueWatch) Watch.push(Json::str(S));
    NN.set("watchedSymbols", std::move(Watch));
    NN.set("sweptByPass",
           ResidueSweptPass.empty() ? Json::null() : Json::str(ResidueSweptPass));
    NN.set("observationIndex",
           ResidueSweptPass.empty() ? Json::null() : Json::integer(ResidueSweptSeq));
    NN.set("familySymbolAbsentAfterPass",
           FamilyAbsencePass.empty() ? Json::null() : Json::str(FamilyAbsencePass));
    NN.set("note", Json::str("the pass a name-based oracle would name as the "
                             "cause: the one that removed the leftover "
                             "declaration, not the one that removed the call"));
    OD.set("nameLookupOracle", std::move(NN));

    OD.set("observationsBetween",
           (HaveZeroPoint && !ResidueSweptPass.empty())
               ? Json::integer(ResidueSweptSeq - ZeroSeq)
               : Json::null());
    OD.set("naiveSaidPresentWhenTheCallLeftTheUnit",
           HaveZeroPoint ? Json::boolean(NaiveAtZero) : Json::null());
    OD.set("moduleWideCallSitesWhenTheCallLeftTheUnit",
           HaveZeroPoint ? Json::integer(ModuleCallsAtZero) : Json::null());
    Json RZ = Json::array();
    for (const std::string &S : ResidueAtZero) RZ.push(Json::str(S));
    OD.set("declaredButUncalledWhenTheCallLeftTheUnit",
           HaveZeroPoint ? std::move(RZ) : Json::null());
    OD.set("totalAfterPassObservations", Json::integer(ObsSeq));
    R.set("oracleDivergence", std::move(OD));

    Json St = Json::object();
    St.set("state", Json::str(stateName(V.S)));
    St.set("reason", Json::str(V.Reason));
    St.set("memoryObjectDiscriminatorEnabled",
           Json::boolean(!C.DisableMemObjDiscriminator));
    // NOT_APPLICABLE is not a pass. The question stopped having a referent, so
    // nothing was verified, and a caller that treats it as clean has swapped
    // "we did not look" for "it is fine" -- the substitution exit code 3 exists
    // to prevent. The record says so here rather than leaving it to be inferred.
    St.set("completesTheCheck",
           Json::boolean(ControlHeld && V.S != State::NotApplicable &&
                         V.S != State::NotObserved));
    R.set("verdict", std::move(St));

    Json Fs = Json::array();
    if (!ControlHeld) {
      Json F = Json::object();
      F.set("id", Json::str("VG-PROP-003"));
      F.set("severity", Json::str("high"));
      F.set("title", Json::str("The measurement's control did not hold"));
      F.set("detail",
            Json::str("The control unit's effect count did not stay above zero "
                      "across the pipeline, so this run cannot distinguish a "
                      "removed effect from an oracle that stopped working. "
                      "Reported as an incomplete check, never as a clean pass."));
      Json W = Json::object();
      W.set("kind", Json::str("ir"));
      W.set("path", Json::str(C.FixtureRel));
      W.set("unit", Json::str(C.ControlFn));
      W.set("pass", Json::null());
      F.set("where", std::move(W));
      Fs.push(std::move(F));
    } else if (V.S == State::Lost && C.Which != Extractor::ForbiddenCallee) {
      Json F = Json::object();
      F.set("id", Json::str("VG-PROP-001"));
      F.set("severity", Json::str("high"));
      F.set("title", Json::str("A declared security property's effect was "
                               "removed by optimisation"));
      F.set("detail", Json::str(V.Reason));
      Json W = Json::object();
      W.set("kind", Json::str("ir"));
      W.set("path", Json::str(C.FixtureRel));
      W.set("unit", Json::str(C.TargetFn));
      W.set("pass", FoundLoss ? Json::str(firstLossPass()) : Json::null());
      F.set("where", std::move(W));
      Fs.push(std::move(F));
    } else if (V.S == State::Present && C.Which == Extractor::ForbiddenCallee) {
      Json F = Json::object();
      F.set("id", Json::str("VG-PROP-002"));
      F.set("severity", Json::str("high"));
      F.set("title", Json::str("A forbidden callee is still called"));
      F.set("detail", Json::str(V.Reason));
      Json W = Json::object();
      W.set("kind", Json::str("ir"));
      W.set("path", Json::str(C.FixtureRel));
      W.set("unit", Json::str(C.TargetFn));
      W.set("pass", Json::null());
      F.set("where", std::move(W));
      Fs.push(std::move(F));
    }
    R.set("findings", std::move(Fs));

    R.set("evidenceDigest", Json::str(Json::digestOf(R)));

    Json Ctx = Json::object();
    const char *SDE = std::getenv("SOURCE_DATE_EPOCH");
    Ctx.set("timeSource", Json::str(SDE ? "SOURCE_DATE_EPOCH" : "wall-clock"));
    Ctx.set("sourceDateEpoch",
            SDE ? Json::integer(static_cast<int64_t>(std::strtoll(SDE, nullptr, 10)))
                : Json::null());
    Ctx.set("generatedAt",
            Json::integer(SDE ? static_cast<int64_t>(std::strtoll(SDE, nullptr, 10))
                              : static_cast<int64_t>(std::time(nullptr))));
    Ctx.set("host", Json::str(envOr("OBS_HOST", "unrecorded")));
    R.set("context", std::move(Ctx));

    std::error_code EC;
    raw_fd_ostream Out(C.OutPath, EC, sys::fs::OF_Text);
    if (EC) {
      errs() << "IrCheckpoints: cannot write " << C.OutPath << ": "
             << EC.message() << "\n";
      return;
    }
    Out << R.serialise() << "\n";
  }

  std::string firstLossPass() const {
    for (const Transition &T : History)
      if (T.Role == "subject" && T.To == 0 && T.From > 0) return T.Pass;
    return "";
  }

  Config C;
  std::string ModuleName;
  UnitFacts Pre, Post, PreCtl, PostCtl;
  std::vector<Transition> History;
  int64_t LastTarget = 0, LastControl = 0, CtlMin = 0;
  bool HaveTarget = false, HaveControl = false, HaveCtlMin = false;
  bool SawPre = false, Emitted = false;
  bool SawZero = false, SawZeroThenNonZero = false;
  bool NaivePre = false, NaivePost = false;
  int64_t ModuleCallsPre = 0, ModuleCallsPost = 0;
  std::vector<std::string> ResiduePost;

  // Oracle-divergence bookkeeping.
  int64_t ObsSeq = 0, ZeroSeq = 0, FamilyAbsenceSeq = 0, ResidueSweptSeq = 0;
  int64_t ModuleCallsAtZero = 0;
  bool HaveZeroPoint = false, NaiveAtZero = false, NaiveWasPresent = false;
  std::string FamilyAbsencePass, ResidueSweptPass;
  std::vector<std::string> ResidueAtZero, ResidueWatch;

  unsigned SnapSeq = 0;
};

std::shared_ptr<Session> TheSession;

struct PreOptObserver : PassInfoMixin<PreOptObserver> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    if (TheSession) TheSession->recordPreOpt(M);
    return PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

struct PostOptObserver : PassInfoMixin<PostOptObserver> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    if (TheSession) TheSession->recordPostOptAndEmit(M);
    return PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "IrCheckpoints", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            Config Cfg = loadConfig();
            if (!Cfg.Valid) return;
            TheSession = std::make_shared<Session>(std::move(Cfg));

            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(PreOptObserver());
                });
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(PostOptObserver());
                });

            if (PassInstrumentationCallbacks *PIC =
                    PB.getPassInstrumentationCallbacks()) {
              auto S = TheSession;
              PIC->registerAfterPassCallback(
                  [S](StringRef PassID, Any IR, const PreservedAnalyses &) {
                    if (const auto **FPtr = any_cast<const Function *>(&IR)) {
                      S->noteModule(PassID, *(*FPtr)->getParent());
                      S->recordAfterPass(PassID, **FPtr);
                      return;
                    }
                    if (const auto **MPtr = any_cast<const Module *>(&IR)) {
                      S->noteModule(PassID, **MPtr);
                      for (const Function &F : **MPtr)
                        if (!F.isDeclaration()) S->recordAfterPass(PassID, F);
                    }
                  });
            }
          }};
}
