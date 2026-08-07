#include "Classifier.h"
#include "Findings.h"

#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TokenKinds.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

#include <algorithm>

using namespace clang;
using namespace clang::ast_matchers;
using namespace llvm;

namespace intentgate {

static constexpr const char *kOutsideRoot = "<outside-root>";

namespace {

std::string normalise(StringRef P) {
  SmallString<256> S(P);
  llvm::sys::path::native(S, llvm::sys::path::Style::posix);
  llvm::sys::path::remove_dots(S, /*remove_dot_dot=*/true, llvm::sys::path::Style::posix);
  return std::string(S.str());
}

std::string realPathOf(StringRef P) {
  SmallString<256> Real;
  if (!llvm::sys::fs::real_path(P, Real))
    return normalise(Real.str());
  SmallString<256> Abs(P);
  llvm::sys::fs::make_absolute(Abs);
  return normalise(Abs.str());
}

/// The name a call to this declaration resolves to at link time. An asm label
/// or an `alias` attribute REDIRECTS the call, so the written identifier is not
/// the target and reporting the written identifier would be a name search
/// wearing an AST costume.
std::string targetNameOf(const FunctionDecl *FD) {
  if (const auto *A = FD->getAttr<AsmLabelAttr>()) {
    StringRef L = A->getLabel();
    L.consume_front("\01"); // the platform mangling escape, not part of the name
    return L.str();
  }
  if (const auto *A = FD->getAttr<AliasAttr>())
    return A->getAliasee().str();
  return FD->getNameAsString();
}

/// Innermost enclosing function body, or "" at file scope. Climbs the parent
/// map rather than relying on a `hasAncestor` matcher, so a call inside a file
/// scope initialiser is described correctly instead of being dropped.
std::string enclosingFunctionName(const Stmt *S, ASTContext &Ctx) {
  SmallVector<DynTypedNode, 8> Work;
  Work.push_back(DynTypedNode::create(*S));
  SmallPtrSet<const void *, 16> Seen;
  while (!Work.empty()) {
    DynTypedNode N = Work.pop_back_val();
    if (const auto *FD = N.get<FunctionDecl>())
      return FD->getNameAsString();
    for (const DynTypedNode &P : Ctx.getParents(N))
      if (Seen.insert(P.getMemoizationData()).second)
        Work.push_back(P);
  }
  return std::string();
}

Site siteOfExpansion(const CallSite &C) {
  Site S;
  S.File = C.ExpansionFile;
  S.Line = C.ExpansionLine;
  S.Function = C.EnclosingFunction;
  S.Indirect = C.Indirect;
  S.ViaMacro = C.ViaMacro;
  return S;
}

class Collector : public MatchFinder::MatchCallback {
public:
  std::vector<const CallExpr *> Calls;
  std::vector<const DeclRefExpr *> Refs;
  std::vector<const FunctionDecl *> Decls;

  void run(const MatchFinder::MatchResult &R) override {
    if (const auto *CE = R.Nodes.getNodeAs<CallExpr>("call"))
      Calls.push_back(CE);
    if (const auto *DRE = R.Nodes.getNodeAs<DeclRefExpr>("ref"))
      Refs.push_back(DRE);
    if (const auto *FD = R.Nodes.getNodeAs<FunctionDecl>("fdecl"))
      Decls.push_back(FD);
  }
};

} // namespace

// ---------------------------------------------------------------------------
// SourceIndex
// ---------------------------------------------------------------------------

SourceIndex::SourceIndex(ASTContext &Ctx, StringRef Root) : Ctx(Ctx), Root(realPathOf(Root)) {
  const SourceManager &SM = Ctx.getSourceManager();
  // `FileID::get` is private, so the file set is walked through the FileInfos
  // map and turned back into FileIDs with `translateFile`, which returns the
  // FIRST inclusion of a file that was included more than once — one identity
  // per file, which is what a finding's path means.
  for (auto It = SM.fileinfo_begin(), E = SM.fileinfo_end(); It != E; ++It) {
    FileEntryRef FE = It->first;
    FileID FID = SM.translateFile(FE);
    if (FID.isInvalid())
      continue;
    StringRef Real = FE.getFileEntry().tryGetRealPathName();
    std::string Key = realPathOf(Real.empty() ? FE.getName() : Real);
    ByRealPath.emplace(Key, FID);
  }
}

FileID SourceIndex::resolve(StringRef FindingPath) const {
  std::string Want = normalise(FindingPath);
  std::string Exact = normalise(Root + "/" + Want);
  auto It = ByRealPath.find(Exact);
  if (It != ByRealPath.end())
    return It->second;
  // Suffix fallback, so a findings file written relative to a different but
  // compatible root still addresses the right file. Requires a full path
  // component boundary, so `x/ab.c` never matches `.../zab.c`.
  std::string Suffix = "/" + Want;
  for (const auto &KV : ByRealPath)
    if (StringRef(KV.first).ends_with(Suffix))
      return KV.second;
  return FileID();
}

bool SourceIndex::isOutsideRoot(FileID FID) const { return relFileOf(FID) == kOutsideRoot; }

std::string SourceIndex::relFileOf(FileID FID) const {
  if (FID.isInvalid())
    return kOutsideRoot;
  auto It = RelCache.find(FID.getHashValue());
  if (It != RelCache.end())
    return It->second;

  const SourceManager &SM = Ctx.getSourceManager();
  std::string Out = kOutsideRoot;
  if (OptionalFileEntryRef FE = SM.getFileEntryRefForID(FID)) {
    StringRef Real = FE->getFileEntry().tryGetRealPathName();
    std::string Abs = realPathOf(Real.empty() ? FE->getName() : Real);
    std::string Prefix = Root + "/";
    if (StringRef(Abs).starts_with(Prefix))
      Out = Abs.substr(Prefix.size());
  }
  RelCache.emplace(FID.getHashValue(), Out);
  return Out;
}

std::string SourceIndex::relFileOf(SourceLocation Loc) const {
  const SourceManager &SM = Ctx.getSourceManager();
  return relFileOf(SM.getFileID(Loc));
}

const SourceIndex::FileFacts &SourceIndex::factsFor(FileID FID) const {
  auto It = FactsCache.find(FID.getHashValue());
  if (It != FactsCache.end())
    return It->second;

  FileFacts Facts;
  const SourceManager &SM = Ctx.getSourceManager();
  llvm::MemoryBufferRef Buf = SM.getBufferOrFake(FID);
  // A RAW lexer, deliberately: it sees the file the way a lexical scanner does,
  // before the preprocessor removes `#if 0` bodies and before macro bodies turn
  // into anything. That is the only stream against which "the scanner matched
  // here" is a meaningful question.
  Lexer Lx(FID, Buf, SM, Ctx.getLangOpts());
  Lx.SetCommentRetentionState(true);
  Token Tok;
  while (true) {
    Lx.LexFromRawLexer(Tok);
    if (Tok.is(tok::eof))
      break;
    SourceLocation B = Tok.getLocation();
    unsigned StartLine = SM.getSpellingLineNumber(B);
    if (Tok.is(tok::raw_identifier)) {
      Facts[StartLine].Identifiers.insert(Tok.getRawIdentifier().str());
      continue;
    }
    if (Tok.is(tok::comment) || tok::isStringLiteral(Tok.getKind()) ||
        Tok.is(tok::char_constant) || Tok.is(tok::wide_char_constant)) {
      unsigned Len = Tok.getLength();
      const char *Data = SM.getCharacterData(B);
      StringRef Text(Data, Len);
      unsigned EndLine =
          SM.getSpellingLineNumber(Len ? B.getLocWithOffset(static_cast<int>(Len) - 1) : B);
      for (unsigned L = StartLine; L <= EndLine; ++L)
        Facts[L].Inert.push_back(Text.str());
    }
  }
  return FactsCache.emplace(FID.getHashValue(), std::move(Facts)).first->second;
}

bool SourceIndex::hasIdentifierOnLine(FileID FID, unsigned L, StringRef Name) const {
  if (FID.isInvalid())
    return false;
  const FileFacts &F = factsFor(FID);
  auto It = F.find(L);
  return It != F.end() && It->second.Identifiers.count(Name.str()) != 0;
}

bool SourceIndex::hasInertOccurrenceOnLine(FileID FID, unsigned L, StringRef Text) const {
  if (FID.isInvalid() || Text.empty())
    return false;
  const FileFacts &F = factsFor(FID);
  auto It = F.find(L);
  if (It == F.end())
    return false;
  for (const std::string &Inert : It->second.Inert)
    if (StringRef(Inert).contains(Text))
      return true;
  return false;
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

Inventory buildInventory(ASTContext &Ctx, const SourceIndex &Src,
                         const std::set<std::string> &Targets) {
  Collector C;
  MatchFinder Finder;
  Finder.addMatcher(callExpr().bind("call"), &C);
  Finder.addMatcher(declRefExpr(to(functionDecl())).bind("ref"), &C);
  Finder.addMatcher(functionDecl().bind("fdecl"), &C);
  Finder.matchAST(Ctx);

  const SourceManager &SM = Ctx.getSourceManager();
  Inventory Inv;

  // Which DeclRefExprs sit in callee position. Computed from the call list
  // rather than with an `unless(hasParent(...))` matcher, because the callee is
  // wrapped in an implicit FunctionToPointerDecay cast whose shape differs
  // between C and C++ and between direct and parenthesised callees.
  SmallPtrSet<const Expr *, 32> CalleeExprs;
  for (const CallExpr *CE : C.Calls)
    CalleeExprs.insert(CE->getCallee()->IgnoreParenImpCasts());

  for (const CallExpr *CE : C.Calls) {
    CallSite S;
    const Expr *Callee = CE->getCallee()->IgnoreParenImpCasts();

    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      S.Target = targetNameOf(FD);
      S.Indirect = false;
      S.Resolved = true;
    } else {
      S.Indirect = true;
      S.Resolved = false;
      // Follow a function pointer to its INITIALISER only. Assignments after
      // the declaration are a declared miss (DERIVATION.md, "declared misses"):
      // following them needs flow, and a guess here manufactures exactly the
      // false positive this gate exists to remove.
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Callee))
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
          if (const Expr *Init = VD->getAnyInitializer())
            if (const auto *IDRE = dyn_cast<DeclRefExpr>(Init->IgnoreParenImpCasts()))
              if (const auto *FD = dyn_cast<FunctionDecl>(IDRE->getDecl())) {
                S.Target = targetNameOf(FD);
                S.Resolved = true;
              }
      if (!S.Resolved) {
        Inv.UnresolvedIndirectCalls++;
        continue;
      }
    }

    if (!Targets.count(S.Target))
      continue;

    SourceLocation L = Callee->getBeginLoc();
    S.ViaMacro = L.isMacroID();
    SourceLocation Sp = SM.getSpellingLoc(L);
    SourceLocation Ex = SM.getExpansionLoc(L);
    S.SpellingLine = SM.getSpellingLineNumber(Sp);
    S.ExpansionLine = SM.getSpellingLineNumber(Ex);
    S.SpellingFile = Src.relFileOf(SM.getFileID(Sp));
    S.ExpansionFile = Src.relFileOf(SM.getFileID(Ex));
    S.EnclosingFunction = enclosingFunctionName(CE, Ctx);
    if (S.ExpansionFile == kOutsideRoot)
      Inv.OutsideRoot++;
    Inv.Calls.push_back(std::move(S));
  }

  for (const DeclRefExpr *DRE : C.Refs) {
    if (CalleeExprs.count(DRE))
      continue; // in callee position: that is a call, already recorded
    const auto *FD = dyn_cast<FunctionDecl>(DRE->getDecl());
    if (!FD)
      continue;
    FunctionRef R;
    R.Target = targetNameOf(FD);
    if (!Targets.count(R.Target))
      continue;
    SourceLocation Sp = SM.getSpellingLoc(DRE->getBeginLoc());
    R.Line = SM.getSpellingLineNumber(Sp);
    R.File = Src.relFileOf(SM.getFileID(Sp));
    R.EnclosingFunction = enclosingFunctionName(DRE, Ctx);
    if (R.File == kOutsideRoot)
      Inv.OutsideRoot++;
    Inv.Refs.push_back(std::move(R));
  }

  for (const FunctionDecl *FD : C.Decls) {
    FunctionDeclSite D;
    D.Written = FD->getNameAsString();
    D.Target = targetNameOf(FD);
    D.HasAsmLabel = FD->hasAttr<AsmLabelAttr>();
    D.IsDefinition = FD->doesThisDeclarationHaveABody();
    if (!Targets.count(D.Target))
      continue;
    SourceLocation Sp = SM.getSpellingLoc(FD->getLocation());
    D.Line = SM.getSpellingLineNumber(Sp);
    D.File = Src.relFileOf(SM.getFileID(Sp));
    if (D.File == kOutsideRoot)
      Inv.OutsideRoot++;
    Inv.Decls.push_back(std::move(D));
  }

  return Inv;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

VerdictRecord classify(const LexicalFinding &F, const Rule *R, const Inventory &Inv,
                       const SourceIndex &Src) {
  VerdictRecord V;
  V.Finding = F;

  // D2 — the rule id is not in the table. Fail closed: an unknown rule is not
  // an absent problem.
  if (!R) {
    V.V = Verdict::Deferred;
    V.R = Reason::UnknownRule;
    return V;
  }

  // D3 — the finding's matched text names none of the rule's targets, so there
  // is nothing to look for. Guessing "probably the first one" would make every
  // later verdict unfalsifiable.
  V.Target = selectTarget(*R, F.Match);
  if (V.Target.empty()) {
    V.V = Verdict::Deferred;
    V.R = Reason::TargetNotDerivable;
    return V;
  }

  // D1 — the finding names a file this translation unit does not contain.
  FileID FID = Src.resolve(F.Path);
  if (FID.isInvalid()) {
    V.V = Verdict::Deferred;
    V.R = Reason::FileNotInUnit;
    return V;
  }

  // D4 — the file is not under the root, so any location we emitted for it
  // would be an absolute path (interfaces.md §5).
  std::string Rel = Src.relFileOf(FID);
  if (Rel == kOutsideRoot) {
    V.V = Verdict::Deferred;
    V.R = Reason::PathNotRelativisable;
    return V;
  }

  // --- Stage A: is the target identifier spelled at this location at all? ----
  // This runs FIRST and is what keeps a string literal on line 5 Rejected in a
  // file that also contains a real call on line 20. A verdict is about one
  // location, never about the file.
  if (!Src.hasIdentifierOnLine(FID, F.Line, V.Target)) {
    StringRef Needle = F.Match.empty() ? StringRef(V.Target) : StringRef(F.Match);
    V.V = Verdict::Rejected;
    V.R = Src.hasInertOccurrenceOnLine(FID, F.Line, Needle) ? Reason::InertLexeme
                                                            : Reason::NoLexeme;
    return V;
  }

  // --- Stage B: a call to the target spelled right here (C1) ---------------
  for (const CallSite &C : Inv.Calls) {
    if (C.Target != V.Target || C.ViaMacro)
      continue;
    if (C.ExpansionFile != Rel || C.ExpansionLine != F.Line)
      continue;
    V.Sites.push_back(siteOfExpansion(C));
  }
  if (!V.Sites.empty()) {
    V.V = Verdict::Confirmed;
    V.R = Reason::DirectCall;
    return V;
  }

  // --- Stage C: the entity is real but lives somewhere else ----------------
  // R1 — a call whose callee token is WRITTEN here and lands elsewhere: a macro
  // body, whether function-like (`#define RUN(c) system(c)`) or an alias
  // (`#define SHELL system`).
  for (const CallSite &C : Inv.Calls) {
    if (C.Target != V.Target || !C.ViaMacro)
      continue;
    if (C.SpellingFile != Rel || C.SpellingLine != F.Line)
      continue;
    V.Sites.push_back(siteOfExpansion(C));
  }
  if (!V.Sites.empty()) {
    V.V = Verdict::Refined;
    V.R = Reason::MacroExpansion;
    return V;
  }

  // R2 — the target's ADDRESS is taken here. The call itself is elsewhere and
  // is spelled with the pointer's name, which no lexical rule for the target
  // can see. Zero resolved indirect sites still yields Refined, not Rejected:
  // the address may leave the translation unit, and "we cannot see the call"
  // is not "there is no call".
  bool RefHere = false;
  for (const FunctionRef &Ref : Inv.Refs)
    if (Ref.Target == V.Target && Ref.File == Rel && Ref.Line == F.Line)
      RefHere = true;
  if (RefHere) {
    for (const CallSite &C : Inv.Calls)
      if (C.Target == V.Target && C.Indirect)
        V.Sites.push_back(siteOfExpansion(C));
    V.V = Verdict::Refined;
    V.R = Reason::AddressTaken;
    return V;
  }

  // R3 / J3 — a declaration of the target sits here. Whether that is a refined
  // pointer or nothing at all depends on one decidable fact: is it called?
  bool DeclHere = false;
  for (const FunctionDeclSite &D : Inv.Decls)
    if (D.Target == V.Target && D.File == Rel && D.Line == F.Line)
      DeclHere = true;
  if (DeclHere) {
    for (const CallSite &C : Inv.Calls)
      if (C.Target == V.Target)
        V.Sites.push_back(siteOfExpansion(C));
    if (!V.Sites.empty()) {
      V.V = Verdict::Refined;
      V.R = Reason::DeclarationOfCalled;
      return V;
    }
    V.V = Verdict::Rejected;
    V.R = Reason::DeclaredNeverCalled;
    return V;
  }

  // J4 — the identifier is spelled here and the AST has nothing at this
  // location: a preprocessor-disabled block, or an unrelated use.
  V.V = Verdict::Rejected;
  V.R = Reason::NoReferent;
  return V;
}

std::vector<VerdictRecord> unreportedSites(const std::vector<VerdictRecord> &Verdicts,
                                           const Inventory &Inv,
                                           const std::vector<Rule> &Rules) {
  std::set<std::pair<std::string, unsigned>> Accounted;
  for (const VerdictRecord &V : Verdicts)
    for (const Site &S : V.Sites)
      Accounted.emplace(S.File, S.Line);

  std::vector<VerdictRecord> Out;
  for (const CallSite &C : Inv.Calls) {
    if (Accounted.count({C.ExpansionFile, C.ExpansionLine}))
      continue;
    const Rule *Owner = nullptr;
    for (const Rule &R : Rules)
      if (std::find(R.Targets.begin(), R.Targets.end(), C.Target) != R.Targets.end()) {
        Owner = &R;
        break;
      }
    if (!Owner)
      continue;
    VerdictRecord V;
    V.FromAstOnly = true;
    V.Finding.Id = Owner->Id;
    V.Finding.Path = C.ExpansionFile;
    V.Finding.Line = C.ExpansionLine;
    V.Target = C.Target;
    V.V = Verdict::Confirmed;
    V.R = C.ViaMacro ? Reason::MacroExpansion : Reason::DirectCall;
    V.Sites.push_back(siteOfExpansion(C));
    Out.push_back(std::move(V));
    Accounted.emplace(C.ExpansionFile, C.ExpansionLine);
  }
  return Out;
}

} // namespace intentgate
