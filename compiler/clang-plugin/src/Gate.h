// Shared vocabulary for the AST gate: what comes in (a lexical finding), what
// the AST says about it (a verdict), and what falls out (a derived
// requirement). DERIVATION.md in this directory is the specification; this
// header is the 1:1 code side of it, and the table at the end of DERIVATION.md
// names the symbols here.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace intentgate {

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// What a rule asks of the rest of the toolchain once the AST has confirmed
/// that the construct is real. This is a property of the RULE, never of the
/// AST: the AST decides whether a requirement is emitted and what its scope is,
/// the rule decides what kind of requirement it would be.
enum class RequirementKind {
  /// The effect observed here must still be observable at every checkpoint.
  /// `LOST` at any of them is a finding. (A secret wipe; a bounds check.)
  MustSurvive,
  /// No call site resolving to the target may exist within scope at any
  /// checkpoint. `PRESENT` is a finding. (A shell escape.)
  MustNotAppear,
  /// The target is absent here now. If it becomes `PRESENT` later, something
  /// introduced it and no permitted origin explains it.
  MustNotBeIntroduced,
  /// No requirement. Emitted (not omitted) for a rejected finding, so that a
  /// later run which DOES produce a requirement is a visible change rather than
  /// a new line appearing from nowhere.
  None,
};

const char *toString(RequirementKind K);
bool parseRequirementKind(const std::string &S, RequirementKind &Out);

struct Rule {
  std::string Id;      ///< e.g. "VG-MEM-006"
  std::string Family;  ///< e.g. "MEM" — the propertyId namespace
  /// Resolved callee names this rule is about. A finding selects exactly one of
  /// them (the longest that occurs in the finding's matched text); if none
  /// occurs, the finding is Deferred rather than guessed at.
  std::vector<std::string> Targets;
  RequirementKind Kind = RequirementKind::None;
  std::vector<std::string> Checkpoints;
};

// ---------------------------------------------------------------------------
// Input: a lexical finding
// ---------------------------------------------------------------------------

/// interfaces.md §2 plus two fields §2 does not have. See README.md
/// "Schema gaps reported upward" — `where.line` and `match` are required to
/// address a finding at all, and are read from `where.line` / `where.column` /
/// `match` (top-level `line`/`column` accepted as an alias).
struct LexicalFinding {
  std::string Id;       ///< rule id
  std::string Severity; ///< low | medium | high | critical
  std::string Path;     ///< as written in the finding; relative to the root
  unsigned Line = 0;
  unsigned Column = 0;
  std::string Match; ///< the text the lexical layer matched
};

// ---------------------------------------------------------------------------
// AST inventory
// ---------------------------------------------------------------------------

/// One call site, described by the ORACLE RULE (interfaces.md §4): identified
/// by walking call expressions and resolving the callee, never by searching for
/// a symbol name in text.
struct CallSite {
  std::string Target;   ///< resolved target name (asm-label / alias aware)
  bool Indirect = false;///< reached through a function pointer
  bool ViaMacro = false;///< the callee token came from a macro expansion
  bool Resolved = true; ///< false: an indirect call whose target we could not name
  unsigned SpellingLine = 0;   ///< where the callee token is WRITTEN
  unsigned ExpansionLine = 0;  ///< where the call LANDS after expansion
  std::string SpellingFile;    ///< relative to the root
  std::string ExpansionFile;   ///< relative to the root
  std::string EnclosingFunction; ///< innermost function body, "" at file scope
};

/// A reference to a function that is NOT in callee position: its address is
/// taken. This is the only thing that makes an indirect call possible in a
/// single translation unit, so it is what the gate looks for when a lexical
/// finding lands on a line with no call on it.
struct FunctionRef {
  std::string Target;
  unsigned Line = 0;
  std::string File;
  std::string EnclosingFunction;
};

/// A declaration or definition of a function whose resolved target name is
/// interesting. Note `AsmLabel`: `extern int f(void) __asm__("system")` is a
/// declaration of `f` whose target is `system`.
struct FunctionDeclSite {
  std::string Written; ///< the identifier as spelled
  std::string Target;  ///< asm label / alias if present, else `Written`
  bool HasAsmLabel = false;
  bool IsDefinition = false;
  unsigned Line = 0;
  std::string File;
};

// ---------------------------------------------------------------------------
// Output: a verdict
// ---------------------------------------------------------------------------

enum class Verdict {
  /// A call site resolving to the target is spelled at this exact location.
  Confirmed,
  /// The construct at this location is not the call, but the call exists and
  /// the location explains how to reach it (macro body, taken address,
  /// declaration of a called function).
  Refined,
  /// This location does not denote the effect. Says nothing about whether the
  /// effect exists elsewhere in the file — that is a different finding's job.
  Rejected,
  /// The check could not be completed. Never merged into Rejected: "we did not
  /// look" reported as "it is clean" is the failure mode this whole directory
  /// is built against (interfaces.md §3, §7).
  Deferred,
};

const char *toString(Verdict V);

/// The decidable reason a verdict came out the way it did. Every one of these
/// is a named branch in Classifier.cpp and a numbered rule in DERIVATION.md.
enum class Reason {
  DirectCall,           ///< C1  -> Confirmed
  MacroExpansion,       ///< R1  -> Refined
  AddressTaken,         ///< R2  -> Refined
  DeclarationOfCalled,  ///< R3  -> Refined
  InertLexeme,          ///< J1  -> Rejected (string literal / comment)
  NoLexeme,             ///< J2  -> Rejected (the text is not even on the line)
  DeclaredNeverCalled,  ///< J3  -> Rejected
  NoReferent,           ///< J4  -> Rejected (preprocessed out, or unrelated)
  FileNotInUnit,        ///< D1  -> Deferred
  UnknownRule,          ///< D2  -> Deferred
  TargetNotDerivable,   ///< D3  -> Deferred
  PathNotRelativisable, ///< D4  -> Deferred
};

const char *toString(Reason R);

struct Site {
  std::string File;
  unsigned Line = 0;
  std::string Function;
  bool Indirect = false;
  bool ViaMacro = false;
};

struct VerdictRecord {
  LexicalFinding Finding;
  std::string Target; ///< the rule target this finding was resolved against
  Verdict V = Verdict::Deferred;
  Reason R = Reason::UnknownRule;
  /// For Refined: where the effect actually is. For Confirmed: the single site.
  /// For Rejected/Deferred: empty.
  std::vector<Site> Sites;
  /// Set when the gate found the construct in the AST with no lexical finding
  /// pointing at it. Not one of the three classes; see README.md.
  bool FromAstOnly = false;
};

// ---------------------------------------------------------------------------
// Output: a derived requirement
// ---------------------------------------------------------------------------

struct Scope {
  std::string Kind; ///< "function" | "file"
  std::string Name; ///< function name, or "" for a file scope
  std::string File;
};

struct DerivedRequirement {
  std::string PropertyId; ///< PROP-<FAMILY>-<8 hex>, a function of the content
  RequirementKind Kind = RequirementKind::None;
  Scope S;
  std::vector<std::string> Checkpoints;
  std::string OracleKind;   ///< always "call-site" today (interfaces.md §4)
  std::string OracleTarget; ///< the resolved callee name to count
  int64_t ExpectedCount = 0;
  /// Provenance: which finding, at which line, with which verdict.
  std::string OriginFindingId;
  unsigned OriginLine = 0;
  Verdict OriginVerdict = Verdict::Deferred;
  std::vector<unsigned> ActualLines;
};

} // namespace intentgate
