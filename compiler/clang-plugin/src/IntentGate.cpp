// IntentGate — a Clang AST plugin that decides whether a lexical finding is
// real.
//
// HOW TO LOAD IT, and the trap that eats an afternoon:
//
//     clang-18 -fplugin=libIntentGate.so \
//              -Xclang -add-plugin -Xclang intent-gate \
//              -Xclang -plugin-arg-intent-gate -Xclang findings=f.json \
//              -c input.c -o input.o
//
// `-Xclang -plugin -Xclang intent-gate` compiles too, and then no object file
// appears. That is not a bug in the plugin: `-plugin` REPLACES the main frontend
// action, so codegen never runs. `-add-plugin` runs the plugin in addition to
// codegen, which is what a gate wants — see README.md, which records the
// measured exit codes for both.
#include "Canonical.h"
#include "Classifier.h"
#include "Derivation.h"
#include "Findings.h"
#include "Gate.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#if __has_include(<dlfcn.h>)
#include <dlfcn.h>
#define INTENTGATE_HAVE_DLADDR 1
#endif
#if __has_include(<unistd.h>)
#include <unistd.h>
#define INTENTGATE_HAVE_GETHOSTNAME 1
#endif

using namespace clang;
using namespace llvm;
using namespace intentgate;

namespace {

struct Options {
  std::string FindingsPath;
  std::string RulesPath;
  std::string Root;
  std::string OutPath;
  bool Quiet = false;
};

std::string isoUtc(std::time_t T) {
  std::tm G{};
#if defined(_WIN32)
  gmtime_s(&G, &T);
#else
  gmtime_r(&T, &G);
#endif
  char Buf[32];
  std::strftime(Buf, sizeof(Buf), "%Y-%m-%dT%H:%M:%SZ", &G);
  return Buf;
}

std::string hostName() {
#ifdef INTENTGATE_HAVE_GETHOSTNAME
  char Buf[256] = {0};
  if (gethostname(Buf, sizeof(Buf) - 1) == 0)
    return Buf;
#endif
  return "unknown";
}

/// The path of this shared object, so the record can pin the thing that
/// produced it. Empty when the platform cannot say.
std::string selfPath() {
#ifdef INTENTGATE_HAVE_DLADDR
  Dl_info Info;
  if (dladdr(reinterpret_cast<void *>(&hostName), &Info) && Info.dli_fname)
    return Info.dli_fname;
#endif
  return std::string();
}

json::Value siteJson(const Site &S) {
  json::Object O;
  O["file"] = S.File;
  O["line"] = static_cast<int64_t>(S.Line);
  O["function"] = S.Function;
  O["indirect"] = S.Indirect;
  O["viaMacro"] = S.ViaMacro;
  return json::Value(std::move(O));
}

json::Value verdictJson(const VerdictRecord &V) {
  json::Object O;
  O["findingId"] = V.Finding.Id;
  O["severity"] = V.Finding.Severity;
  O["target"] = V.Target;
  O["verdict"] = std::string(toString(V.V));
  O["reason"] = std::string(toString(V.R));
  json::Object Lex;
  Lex["file"] = V.Finding.Path;
  Lex["line"] = static_cast<int64_t>(V.Finding.Line);
  Lex["column"] = static_cast<int64_t>(V.Finding.Column);
  Lex["match"] = V.Finding.Match;
  O["lexical"] = json::Value(std::move(Lex));
  json::Array Sites;
  for (const Site &S : V.Sites)
    Sites.push_back(siteJson(S));
  O["sites"] = json::Value(std::move(Sites));
  return json::Value(std::move(O));
}

json::Value requirementJson(const DerivedRequirement &D) {
  json::Object O;
  O["propertyId"] = D.PropertyId;
  O["kind"] = std::string(toString(D.Kind));
  json::Object S;
  S["kind"] = D.S.Kind;
  S["name"] = D.S.Name;
  S["file"] = D.S.File;
  O["scope"] = json::Value(std::move(S));
  json::Array Cp;
  for (const std::string &C : D.Checkpoints)
    Cp.push_back(C);
  O["checkpoints"] = json::Value(std::move(Cp));
  json::Object Or;
  Or["kind"] = D.OracleKind;
  Or["target"] = D.OracleTarget;
  Or["expectedCount"] = D.ExpectedCount;
  O["oracle"] = json::Value(std::move(Or));
  json::Object Origin;
  Origin["findingId"] = D.OriginFindingId;
  Origin["line"] = static_cast<int64_t>(D.OriginLine);
  Origin["verdict"] = std::string(toString(D.OriginVerdict));
  json::Array Lines;
  for (unsigned L : D.ActualLines)
    Lines.push_back(static_cast<int64_t>(L));
  Origin["actualLines"] = json::Value(std::move(Lines));
  O["origin"] = json::Value(std::move(Origin));
  return json::Value(std::move(O));
}

class GateConsumer : public ASTConsumer {
public:
  GateConsumer(CompilerInstance &CI, Options Opts) : CI(CI), Opts(std::move(Opts)) {}

  void HandleTranslationUnit(ASTContext &Ctx) override {
    DiagnosticsEngine &DE = CI.getDiagnostics();
    const unsigned ErrId = DE.getCustomDiagID(DiagnosticsEngine::Error, "IntentGate: %0");
    const unsigned WarnId = DE.getCustomDiagID(DiagnosticsEngine::Warning, "IntentGate: %0");

    std::vector<Rule> Rules;
    std::string Err;
    if (!Opts.RulesPath.empty()) {
      if (!loadRules(Opts.RulesPath, Rules, Err)) {
        DE.Report(ErrId) << Err;
        return;
      }
    } else {
      Rules = builtinRules();
    }

    std::vector<LexicalFinding> Findings;
    if (!loadFindings(Opts.FindingsPath, Findings, Err)) {
      DE.Report(ErrId) << Err;
      return;
    }

    SourceManager &SM = Ctx.getSourceManager();
    std::string MainFile;
    if (OptionalFileEntryRef FE = SM.getFileEntryRefForID(SM.getMainFileID()))
      MainFile = FE->getName().str();

    std::string Root = Opts.Root;
    if (Root.empty()) {
      SmallString<256> P(MainFile);
      llvm::sys::path::remove_filename(P);
      llvm::sys::fs::make_absolute(P);
      Root = std::string(P.str());
    }

    SourceIndex Src(Ctx, Root);

    std::set<std::string> Targets;
    for (const Rule &R : Rules)
      for (const std::string &T : R.Targets)
        Targets.insert(T);

    Inventory Inv = buildInventory(Ctx, Src, Targets);

    std::vector<VerdictRecord> Verdicts;
    Verdicts.reserve(Findings.size());
    for (const LexicalFinding &F : Findings)
      Verdicts.push_back(classify(F, findRule(Rules, F.Id), Inv, Src));

    std::vector<VerdictRecord> AstOnly = unreportedSites(Verdicts, Inv, Rules);

    std::vector<VerdictRecord> All = Verdicts;
    All.insert(All.end(), AstOnly.begin(), AstOnly.end());
    std::vector<DerivedRequirement> Reqs = derive(All, Rules, Inv);

    // --- diagnostics -------------------------------------------------------
    // Warnings only. An error here would stop codegen and no object file would
    // be produced, which would make the gate the thing that changed the build.
    if (!Opts.Quiet) {
      for (const VerdictRecord &V : Verdicts) {
        std::string Msg = std::string(toString(V.V)) + " " + V.Finding.Id + " (" + V.Target +
                          ") — " + toString(V.R);
        if (!V.Sites.empty()) {
          Msg += "; actual at";
          for (const Site &S : V.Sites)
            Msg += " " + S.File + ":" + std::to_string(S.Line);
        }
        SourceLocation L = locFor(SM, Src, V.Finding);
        if (L.isValid())
          DE.Report(L, WarnId) << Msg;
        else
          DE.Report(WarnId) << Msg;
      }
      for (const VerdictRecord &V : AstOnly)
        DE.Report(WarnId) << ("unreported call site: " + V.Target + " at " + V.Finding.Path + ":" +
                              std::to_string(V.Finding.Line) +
                              " has no lexical finding pointing at it");
    }

    // --- record ------------------------------------------------------------
    if (Opts.OutPath.empty())
      return;

    json::Object Top;
    Top["schema"] = "intent-gate/v1";

    std::string TuRel = Src.relFileOf(SM.getMainFileID());
    Top["translationUnit"] = TuRel;

    int64_t NConfirmed = 0, NRefined = 0, NRejected = 0, NDeferred = 0;
    json::Array VerdictArr;
    for (const VerdictRecord &V : Verdicts) {
      switch (V.V) {
      case Verdict::Confirmed:
        NConfirmed++;
        break;
      case Verdict::Refined:
        NRefined++;
        break;
      case Verdict::Rejected:
        NRejected++;
        break;
      case Verdict::Deferred:
        NDeferred++;
        break;
      }
      VerdictArr.push_back(verdictJson(V));
    }
    Top["verdicts"] = json::Value(std::move(VerdictArr));

    json::Array AstOnlyArr;
    for (const VerdictRecord &V : AstOnly)
      AstOnlyArr.push_back(verdictJson(V));
    Top["astOnly"] = json::Value(std::move(AstOnlyArr));

    json::Array ReqArr;
    for (const DerivedRequirement &D : Reqs)
      ReqArr.push_back(requirementJson(D));
    Top["requirements"] = json::Value(std::move(ReqArr));

    json::Object Sum;
    Sum["confirmed"] = NConfirmed;
    Sum["refined"] = NRefined;
    Sum["rejected"] = NRejected;
    Sum["deferred"] = NDeferred;
    Sum["astOnly"] = static_cast<int64_t>(AstOnly.size());
    Sum["requirements"] = static_cast<int64_t>(Reqs.size());
    Sum["callSites"] = static_cast<int64_t>(Inv.Calls.size());
    Sum["unresolvedIndirectCalls"] = Inv.UnresolvedIndirectCalls;
    Sum["outsideRoot"] = Inv.OutsideRoot;
    Top["summary"] = json::Value(std::move(Sum));

    // toolchain: outside `context`, therefore digested. The pin is PARTIAL and
    // says so: it covers the plugin module and the clang version string, not
    // every package in the toolchain. Completing it is the driver's job, and a
    // partial pin named as partial is better than a full-looking one that is not.
    json::Object Tc;
    Tc["clang"] = std::string(CLANG_VERSION_STRING);
    json::Array Pkgs;
    std::string Self = selfPath();
    std::string SelfDigest;
    if (!Self.empty() && sha256File(Self, SelfDigest)) {
      json::Object P;
      P["name"] = "IntentGate";
      P["sha256"] = SelfDigest;
      Pkgs.push_back(json::Value(std::move(P)));
    }
    Tc["packages"] = json::Value(std::move(Pkgs));
    Tc["coverage"] = "partial: plugin module and clang version only";
    {
      json::Object PinCopy;
      PinCopy["clang"] = Tc["clang"];
      PinCopy["packages"] = Tc["packages"];
      std::string Canon, E2;
      if (canonicalize(json::Value(std::move(PinCopy)), Canon, E2))
        Tc["digest"] = sha256Hex(Canon);
      else
        Tc["digest"] = "";
    }
    Top["toolchain"] = json::Value(std::move(Tc));

    // context: everything a re-run cannot reproduce, and nothing else. Recorded,
    // never digested.
    json::Object Ctxt;
    const char *Sde = std::getenv("SOURCE_DATE_EPOCH");
    int64_t Epoch = Sde ? std::strtoll(Sde, nullptr, 10) : static_cast<int64_t>(std::time(nullptr));
    Ctxt["generatedAt"] = isoUtc(static_cast<std::time_t>(Epoch));
    Ctxt["timeSource"] = Sde ? "SOURCE_DATE_EPOCH" : "wall-clock";
    Ctxt["sourceDateEpoch"] = Epoch;
    Ctxt["host"] = hostName();
    Ctxt["repository"] = nullptr; // provenance is the driver's to fill
    Top["context"] = json::Value(std::move(Ctxt));

    std::string Digest;
    if (!evidenceDigest(Top, Digest, Err)) {
      DE.Report(ErrId) << ("record is malformed: " + Err);
      return;
    }
    Top["evidenceDigest"] = Digest;

    std::string Canon;
    if (!canonicalize(json::Value(std::move(Top)), Canon, Err)) {
      DE.Report(ErrId) << ("record is malformed: " + Err);
      return;
    }

    std::error_code EC;
    raw_fd_ostream OS(Opts.OutPath, EC, llvm::sys::fs::OF_Text);
    if (EC) {
      DE.Report(ErrId) << ("cannot write " + Opts.OutPath + ": " + EC.message());
      return;
    }
    OS << Canon << "\n";
  }

private:
  static SourceLocation locFor(SourceManager &SM, const SourceIndex &Src,
                               const LexicalFinding &F) {
    FileID FID = Src.resolve(F.Path);
    if (FID.isInvalid())
      return SourceLocation();
    return SM.translateLineCol(FID, F.Line, F.Column ? F.Column : 1);
  }

  CompilerInstance &CI;
  Options Opts;
};

class IntentGateAction : public PluginASTAction {
protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef) override {
    return std::make_unique<GateConsumer>(CI, Opts);
  }

  bool ParseArgs(const CompilerInstance &CI, const std::vector<std::string> &Args) override {
    DiagnosticsEngine &DE = const_cast<CompilerInstance &>(CI).getDiagnostics();
    const unsigned ErrId = DE.getCustomDiagID(DiagnosticsEngine::Error, "IntentGate: %0");
    for (const std::string &A : Args) {
      StringRef S(A);
      if (S.consume_front("findings="))
        Opts.FindingsPath = S.str();
      else if (S.consume_front("rules="))
        Opts.RulesPath = S.str();
      else if (S.consume_front("root="))
        Opts.Root = S.str();
      else if (S.consume_front("out="))
        Opts.OutPath = S.str();
      else if (S == "quiet")
        Opts.Quiet = true;
      else {
        DE.Report(ErrId) << ("unknown plugin argument '" + A +
                             "'; accepted: findings=, rules=, root=, out=, quiet");
        return false;
      }
    }
    // Fail closed (interfaces.md §7): a gate that was asked for and cannot run
    // must not look like a gate that ran and found nothing.
    if (Opts.FindingsPath.empty()) {
      DE.Report(ErrId) << "findings=<path> is required";
      return false;
    }
    return true;
  }

  // AddAfterMainAction, not ReplaceAction. This is the whole reason an object
  // file still appears; see the header comment.
  ActionType getActionType() override { return AddAfterMainAction; }

private:
  Options Opts;
};

} // namespace

static FrontendPluginRegistry::Add<IntentGateAction>
    X("intent-gate", "confirm, reject or refine lexical findings against the AST");
