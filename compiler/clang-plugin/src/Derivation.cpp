#include "Derivation.h"
#include "Canonical.h"
#include "Findings.h"

#include "llvm/Support/JSON.h"

#include <algorithm>
#include <set>

using namespace llvm;

namespace intentgate {

const std::vector<std::string> &defaultCheckpoints(RequirementKind K) {
  // must-survive needs a pre-optimisation reading, because "it was there before
  // the optimiser and gone after" is the only way to attribute a loss to a
  // pass. must-not-appear needs `link`, because a forbidden symbol can arrive
  // from a library that no source file mentions. must-not-be-introduced starts
  // after the optimiser, because that is the first point at which something can
  // appear that the source did not write.
  static const std::vector<std::string> Survive = {"ast", "ir-pre-opt", "ir-post-opt", "object"};
  static const std::vector<std::string> NotAppear = {"ast", "ir-post-opt", "object", "link"};
  static const std::vector<std::string> NotIntroduced = {"ir-post-opt", "object", "link",
                                                         "artifact"};
  static const std::vector<std::string> None = {};
  switch (K) {
  case RequirementKind::MustSurvive:
    return Survive;
  case RequirementKind::MustNotAppear:
    return NotAppear;
  case RequirementKind::MustNotBeIntroduced:
    return NotIntroduced;
  case RequirementKind::None:
    return None;
  }
  return None;
}

namespace {

/// Scope, decided by one rule with no discretion in it: a requirement is
/// function-scoped exactly when every site it covers lies in one and the same
/// function body. Anything else is file-scoped, including the mixed case, which
/// is the conservative direction (a file scope observes a superset).
Scope scopeOf(const std::vector<Site> &Sites, const std::string &FallbackFile) {
  Scope S;
  S.File = FallbackFile;
  if (Sites.empty()) {
    S.Kind = "file";
    return S;
  }
  std::set<std::string> Fns;
  std::set<std::string> Files;
  for (const Site &Si : Sites) {
    Fns.insert(Si.Function);
    Files.insert(Si.File);
  }
  if (Files.size() == 1)
    S.File = *Files.begin();
  if (Files.size() == 1 && Fns.size() == 1 && !Fns.begin()->empty()) {
    S.Kind = "function";
    S.Name = *Fns.begin();
    return S;
  }
  S.Kind = "file";
  return S;
}

/// Call sites of `Target` inside `S`, counted with the oracle rule: call sites,
/// within one unit, never a symbol-name search (interfaces.md §4).
int64_t countInScope(const Inventory &Inv, const std::string &Target, const Scope &S) {
  int64_t N = 0;
  for (const CallSite &C : Inv.Calls) {
    if (C.Target != Target)
      continue;
    if (C.ExpansionFile != S.File)
      continue;
    if (S.Kind == "function" && C.EnclosingFunction != S.Name)
      continue;
    N++;
  }
  return N;
}

/// A property id that is a function of the property, not of the run: same rule,
/// same target, same scope, same id, on any machine and in any order.
std::string propertyId(const std::string &Family, const std::string &RuleId,
                       const std::string &Target, const Scope &S) {
  json::Object K;
  K["rule"] = RuleId;
  K["target"] = Target;
  K["scopeKind"] = S.Kind;
  K["scopeName"] = S.Name;
  K["file"] = S.File;
  std::string Canon, Err;
  if (!canonicalize(json::Value(std::move(K)), Canon, Err))
    return "PROP-" + Family + "-00000000";
  return "PROP-" + Family + "-" + sha256Hex(Canon).substr(0, 8);
}

} // namespace

std::vector<DerivedRequirement> derive(const std::vector<VerdictRecord> &Verdicts,
                                       const std::vector<Rule> &Rules, const Inventory &Inv) {
  std::vector<DerivedRequirement> Out;

  for (const VerdictRecord &V : Verdicts) {
    const Rule *R = findRule(Rules, V.Finding.Id);
    if (!R)
      continue; // Deferred(D2) already; nothing derivable

    // Deferred emits nothing. Not a `none` requirement: `none` is a claim that
    // nothing is required here, and we do not know that.
    if (V.V == Verdict::Deferred)
      continue;

    DerivedRequirement D;
    D.OracleKind = "call-site";
    D.OracleTarget = V.Target;
    D.OriginFindingId = V.Finding.Id;
    D.OriginLine = V.Finding.Line;
    D.OriginVerdict = V.V;
    for (const Site &S : V.Sites)
      D.ActualLines.push_back(S.Line);

    if (V.V == Verdict::Confirmed || V.V == Verdict::Refined) {
      // D-1 / D-2. The rule supplies the kind; the AST supplies everything else.
      D.Kind = R->Kind;
      D.S = scopeOf(V.Sites, V.Finding.Path);
      D.Checkpoints = R->Checkpoints.empty() ? defaultCheckpoints(D.Kind) : R->Checkpoints;
      D.ExpectedCount = countInScope(Inv, V.Target, D.S);
    } else {
      // D-3 / D-4. Rejected. The location does not denote the effect, so no
      // must-survive / must-not-appear requirement follows from it. But if the
      // rule is must-not-appear AND the whole unit contains zero call sites of
      // the target, then the unit is currently clean of it, and "clean now" is
      // a checkable property going forward: anything that makes it appear later
      // had no permitted origin.
      int64_t Total = 0;
      for (const CallSite &C : Inv.Calls)
        if (C.Target == V.Target)
          Total++;
      Scope S;
      S.Kind = "file";
      S.File = V.Finding.Path;
      D.S = S;
      if (R->Kind == RequirementKind::MustNotAppear && Total == 0) {
        D.Kind = RequirementKind::MustNotBeIntroduced;
        D.Checkpoints = defaultCheckpoints(D.Kind);
        D.ExpectedCount = 0;
      } else {
        D.Kind = RequirementKind::None;
        D.Checkpoints = defaultCheckpoints(RequirementKind::None);
        D.ExpectedCount = 0;
      }
    }

    D.PropertyId = propertyId(R->Family, R->Id, V.Target, D.S);
    Out.push_back(std::move(D));
  }

  // Two findings that land on the same property (the same rule, target and
  // scope) are one requirement. Order is by property id so the array is stable
  // across runs; §5 rule 2 says array order is significant and never sorted for
  // the DIGEST, which is exactly why it has to be made deterministic here
  // rather than left to matcher traversal order.
  std::stable_sort(Out.begin(), Out.end(),
                   [](const DerivedRequirement &A, const DerivedRequirement &B) {
                     if (A.PropertyId != B.PropertyId)
                       return A.PropertyId < B.PropertyId;
                     return A.OriginLine < B.OriginLine;
                   });
  std::vector<DerivedRequirement> Merged;
  for (DerivedRequirement &D : Out) {
    if (!Merged.empty() && Merged.back().PropertyId == D.PropertyId &&
        Merged.back().Kind == D.Kind) {
      for (unsigned L : D.ActualLines)
        Merged.back().ActualLines.push_back(L);
      continue;
    }
    Merged.push_back(std::move(D));
  }
  for (DerivedRequirement &D : Merged) {
    std::sort(D.ActualLines.begin(), D.ActualLines.end());
    D.ActualLines.erase(std::unique(D.ActualLines.begin(), D.ActualLines.end()),
                        D.ActualLines.end());
  }
  return Merged;
}

} // namespace intentgate
