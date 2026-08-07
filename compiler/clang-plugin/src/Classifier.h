// The AST side of the gate: build an inventory of what the translation unit
// actually contains, then answer, per lexical finding, which of the four
// verdicts applies. Every branch is decidable from the inventory plus a raw
// re-lex of the finding's line; there is no "judge from context" step.
#pragma once

#include "Gate.h"

#include "clang/AST/ASTContext.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/StringRef.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace intentgate {

struct Inventory {
  std::vector<CallSite> Calls;
  std::vector<FunctionRef> Refs;
  std::vector<FunctionDeclSite> Decls;
  /// Indirect calls whose callee could not be named. Counted, never silently
  /// dropped: an unresolvable callee is "we could not tell", and reporting that
  /// as "no such call" is the conflation interfaces.md §3 exists to prevent.
  int64_t UnresolvedIndirectCalls = 0;
  /// Inventory entries whose file lies outside the fixture root. Their paths
  /// are recorded as "<outside-root>" because §5 forbids an absolute path in a
  /// record; the count is here so the omission is visible.
  int64_t OutsideRoot = 0;
};

/// Maps between source locations, root-relative paths, and the raw token stream
/// a lexical scanner would have seen. Caches per-file lexing.
class SourceIndex {
public:
  SourceIndex(clang::ASTContext &Ctx, llvm::StringRef Root);

  /// The FileID whose real path is `<root>/<FindingPath>`, or whose real path
  /// ends with `/<FindingPath>`. Invalid FileID when the file is not part of
  /// this translation unit.
  clang::FileID resolve(llvm::StringRef FindingPath) const;

  /// Root-relative path of a file, or "<outside-root>" when it is not under the
  /// root. Never absolute.
  std::string relFileOf(clang::FileID FID) const;
  std::string relFileOf(clang::SourceLocation Loc) const;
  bool isOutsideRoot(clang::FileID FID) const;

  /// Is the identifier `Name` spelled as an IDENTIFIER token on line `L`?
  /// Answered from a raw re-lex, so a macro definition body counts, an `#if 0`
  /// body counts, and text inside a string or a comment does not.
  bool hasIdentifierOnLine(clang::FileID FID, unsigned L, llvm::StringRef Name) const;

  /// Does `Text` occur inside a comment, string literal or character constant
  /// that covers line `L`? Block comments count on every line they span.
  bool hasInertOccurrenceOnLine(clang::FileID FID, unsigned L, llvm::StringRef Text) const;

  const std::string &root() const { return Root; }

private:
  struct LineFacts {
    std::set<std::string> Identifiers;
    std::vector<std::string> Inert;
  };
  using FileFacts = std::map<unsigned, LineFacts>;

  const FileFacts &factsFor(clang::FileID FID) const;

  clang::ASTContext &Ctx;
  std::string Root;
  std::map<std::string, clang::FileID> ByRealPath;
  mutable std::map<int, FileFacts> FactsCache;
  mutable std::map<int, std::string> RelCache;
};

/// Walk the translation unit with ASTMatchers and record every call site,
/// address-taken function reference and declaration whose RESOLVED target name
/// is one the rule table cares about. Call sites come from `CallBase`-shaped
/// nodes and a resolved callee, never from a name search (interfaces.md §4).
Inventory buildInventory(clang::ASTContext &Ctx, const SourceIndex &Src,
                         const std::set<std::string> &Targets);

/// Classify one lexical finding. `R` may be null (the rule id is unknown).
VerdictRecord classify(const LexicalFinding &F, const Rule *R, const Inventory &Inv,
                       const SourceIndex &Src);

/// Call sites of a rule target that no verdict in `Verdicts` accounts for.
/// Not one of the three classes; this is the gate finding something the lexical
/// layer missed, and it is reported separately so the three classes stay clean.
std::vector<VerdictRecord> unreportedSites(const std::vector<VerdictRecord> &Verdicts,
                                           const Inventory &Inv, const std::vector<Rule> &Rules);

} // namespace intentgate
