#include "Findings.h"

#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace intentgate {

const char *toString(RequirementKind K) {
  switch (K) {
  case RequirementKind::MustSurvive:
    return "must-survive";
  case RequirementKind::MustNotAppear:
    return "must-not-appear";
  case RequirementKind::MustNotBeIntroduced:
    return "must-not-be-introduced";
  case RequirementKind::None:
    return "none";
  }
  return "none";
}

bool parseRequirementKind(const std::string &S, RequirementKind &Out) {
  if (S == "must-survive") {
    Out = RequirementKind::MustSurvive;
    return true;
  }
  if (S == "must-not-appear") {
    Out = RequirementKind::MustNotAppear;
    return true;
  }
  if (S == "must-not-be-introduced") {
    Out = RequirementKind::MustNotBeIntroduced;
    return true;
  }
  if (S == "none") {
    Out = RequirementKind::None;
    return true;
  }
  return false;
}

const char *toString(Verdict V) {
  switch (V) {
  case Verdict::Confirmed:
    return "Confirmed";
  case Verdict::Refined:
    return "Refined";
  case Verdict::Rejected:
    return "Rejected";
  case Verdict::Deferred:
    return "Deferred";
  }
  return "Deferred";
}

const char *toString(Reason R) {
  switch (R) {
  case Reason::DirectCall:
    return "direct-call";
  case Reason::MacroExpansion:
    return "macro-expansion";
  case Reason::AddressTaken:
    return "address-taken";
  case Reason::DeclarationOfCalled:
    return "declaration-of-called";
  case Reason::InertLexeme:
    return "inert-lexeme";
  case Reason::NoLexeme:
    return "no-lexeme";
  case Reason::DeclaredNeverCalled:
    return "declared-never-called";
  case Reason::NoReferent:
    return "no-referent";
  case Reason::FileNotInUnit:
    return "file-not-in-translation-unit";
  case Reason::UnknownRule:
    return "unknown-rule";
  case Reason::TargetNotDerivable:
    return "target-not-derivable";
  case Reason::PathNotRelativisable:
    return "path-not-relativisable";
  }
  return "unknown-rule";
}

namespace {

bool readJson(StringRef Path, json::Value &Out, std::string &Err) {
  ErrorOr<std::unique_ptr<MemoryBuffer>> Buf = MemoryBuffer::getFile(Path, /*IsText=*/true);
  if (!Buf) {
    Err = ("cannot read " + Path + ": " + Buf.getError().message()).str();
    return false;
  }
  Expected<json::Value> V = json::parse((*Buf)->getBuffer());
  if (!V) {
    Err = ("cannot parse " + Path + ": " + toString(V.takeError())).str();
    return false;
  }
  Out = std::move(*V);
  return true;
}

/// Read an unsigned that must be present and integral. Anything else is an
/// error rather than a zero, because line 0 is not a location.
bool readUnsigned(const json::Object &O, StringRef Key, unsigned &Out) {
  const json::Value *V = O.get(Key);
  if (!V)
    return false;
  std::optional<int64_t> I = V->getAsInteger();
  if (!I || *I < 0)
    return false;
  Out = static_cast<unsigned>(*I);
  return true;
}

} // namespace

bool loadFindings(StringRef Path, std::vector<LexicalFinding> &Out, std::string &Err) {
  json::Value Root = nullptr;
  if (!readJson(Path, Root, Err))
    return false;

  const json::Array *Arr = Root.getAsArray();
  if (!Arr) {
    const json::Object *O = Root.getAsObject();
    if (O)
      Arr = O->getArray("findings");
  }
  if (!Arr) {
    Err = ("findings file " + Path + " is neither an array nor an object with a `findings` array")
              .str();
    return false;
  }

  std::vector<LexicalFinding> Parsed;
  for (const json::Value &E : *Arr) {
    const json::Object *O = E.getAsObject();
    if (!O) {
      Err = "findings array contains a non-object element";
      return false;
    }
    LexicalFinding F;
    if (std::optional<StringRef> S = O->getString("id"))
      F.Id = S->str();
    else {
      Err = "a finding has no `id`";
      return false;
    }
    if (std::optional<StringRef> S = O->getString("severity"))
      F.Severity = S->str();

    // interfaces.md §2 puts the location under `where`. `line`/`column` are NOT
    // in that shape; see README.md "Schema gaps reported upward". Accept them
    // under `where` (preferred) or at the top level (alias).
    const json::Object *W = O->getObject("where");
    if (W) {
      if (std::optional<StringRef> S = W->getString("path"))
        F.Path = S->str();
      readUnsigned(*W, "line", F.Line);
      readUnsigned(*W, "column", F.Column);
    }
    if (F.Path.empty())
      if (std::optional<StringRef> S = O->getString("path"))
        F.Path = S->str();
    if (F.Line == 0)
      readUnsigned(*O, "line", F.Line);
    if (F.Column == 0)
      readUnsigned(*O, "column", F.Column);
    if (std::optional<StringRef> S = O->getString("match"))
      F.Match = S->str();

    if (F.Path.empty() || F.Line == 0) {
      Err = "finding " + F.Id + " has no addressable location (path and line are both required)";
      return false;
    }
    Parsed.push_back(std::move(F));
  }
  Out = std::move(Parsed);
  return true;
}

bool loadRules(StringRef Path, std::vector<Rule> &Out, std::string &Err) {
  json::Value Root = nullptr;
  if (!readJson(Path, Root, Err))
    return false;

  const json::Array *Arr = Root.getAsArray();
  if (!Arr) {
    const json::Object *O = Root.getAsObject();
    if (O)
      Arr = O->getArray("rules");
  }
  if (!Arr) {
    Err = ("rules file " + Path + " is neither an array nor an object with a `rules` array").str();
    return false;
  }

  std::vector<Rule> Parsed;
  for (const json::Value &E : *Arr) {
    const json::Object *O = E.getAsObject();
    if (!O) {
      Err = "rules array contains a non-object element";
      return false;
    }
    Rule R;
    if (std::optional<StringRef> S = O->getString("id"))
      R.Id = S->str();
    else {
      Err = "a rule has no `id`";
      return false;
    }
    if (std::optional<StringRef> S = O->getString("family"))
      R.Family = S->str();
    if (const json::Array *T = O->getArray("targets"))
      for (const json::Value &V : *T)
        if (std::optional<StringRef> S = V.getAsString())
          R.Targets.push_back(S->str());
    if (R.Targets.empty()) {
      Err = "rule " + R.Id + " has no `targets`; a rule with no target cannot be checked";
      return false;
    }
    std::string KindStr;
    if (std::optional<StringRef> S = O->getString("requirementKind"))
      KindStr = S->str();
    if (!parseRequirementKind(KindStr, R.Kind)) {
      Err = "rule " + R.Id + " has an unknown `requirementKind`: '" + KindStr + "'";
      return false;
    }
    if (const json::Array *C = O->getArray("checkpoints"))
      for (const json::Value &V : *C)
        if (std::optional<StringRef> S = V.getAsString())
          R.Checkpoints.push_back(S->str());
    Parsed.push_back(std::move(R));
  }
  Out = std::move(Parsed);
  return true;
}

const std::vector<Rule> &builtinRules() {
  static const std::vector<Rule> Table = {
      {"VG-CEXEC-001",
       "CEXEC",
       {"system", "popen"},
       RequirementKind::MustNotAppear,
       {"ast", "ir-post-opt", "object", "link"}},
      {"VG-CEXEC-002",
       "CEXEC",
       {"execl", "execlp", "execle", "execv", "execvp", "execvpe"},
       RequirementKind::MustNotAppear,
       {"ast", "ir-post-opt", "object", "link"}},
      {"VG-MEM-001",
       "MEM",
       {"gets"},
       RequirementKind::MustNotAppear,
       {"ast", "ir-post-opt", "object", "link"}},
      {"VG-MEM-002",
       "MEM",
       {"strcpy", "strcat", "sprintf", "vsprintf"},
       RequirementKind::MustNotAppear,
       {"ast", "ir-post-opt", "object", "link"}},
      {"VG-MEM-006",
       "MEM",
       {"memset"},
       RequirementKind::MustSurvive,
       {"ast", "ir-pre-opt", "ir-post-opt", "object"}},
      {"VG-CWIPE-001",
       "CWIPE",
       {"explicit_bzero", "memset_s"},
       RequirementKind::MustSurvive,
       {"ast", "ir-pre-opt", "ir-post-opt", "object"}},
  };
  return Table;
}

const Rule *findRule(const std::vector<Rule> &Rules, StringRef Id) {
  for (const Rule &R : Rules)
    if (R.Id == Id)
      return &R;
  return nullptr;
}

std::string selectTarget(const Rule &R, StringRef MatchText) {
  // Longest wins, so a rule listing both `exec` and `execvp` resolves `execvp(`
  // to `execvp`. Ties are impossible: two distinct targets of the same length
  // cannot both be substrings at the same position, and if both occur the
  // longer-or-equal-first ordering is still deterministic because `Targets` has
  // a fixed order in the table.
  std::string Best;
  for (const std::string &T : R.Targets) {
    if (MatchText.contains(T) && T.size() > Best.size())
      Best = T;
  }
  return Best;
}

} // namespace intentgate
