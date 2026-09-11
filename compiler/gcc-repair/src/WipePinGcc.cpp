// WipePinGcc -- the GCC twin of WipePin, and deliberately invasive in the same
// way.
//
// This plugin changes the object file on purpose. Everything under compiler/
// that loads into a compiler as an observer is measured to leave the output
// byte-identical; this one exists to make the output different, in one narrow
// way: directly after each zero-fill __builtin_memset in a selected function it
// inserts
//
//     __asm__ __volatile__("" : : "g"(dest) : "memory");
//
// An asm the optimiser must keep, that may read the buffer through `dest` and
// may read any memory at all. A memset whose bytes such an asm may read is not
// a dead store, so no later pass may delete it. That it actually survives to
// the assembly is measured (README.md), not assumed.
//
// The LLVM twin (compiler/llvm-repair/src/WipePin.cpp) sets the volatile flag
// on llvm.memset. GCC's GIMPLE has no volatile memset call to mark, so the
// barrier is the pin. The contract both follow is the `wipe-pin-v2` record.
//
// It is the "repair" in find -> repair -> confirm, and never the "confirm": the
// record says what this pass did to GIMPLE, and whether the wipe then reached
// the assembly is decided by the same stock observation that found it missing,
// re-run with this plugin loaded.
//
// Where the pass sits, measured with -fdump-passes on gcc-13 13.3.0 (README.md,
// "Where the pass runs"): directly after `cfg`, the pass that builds the CFG of
// the lowered body. That is inside all_lowering_passes, which run for every
// function at every level including -O0, and it is before `ssa`, before
// `einline` and before `dse1` -- before anything that inlines, and before
// anything that could delete the memset. A pass placed after them would find
// nothing left to pin in exactly the cases it exists for. Before `ssa` also
// means the pin needs no SSA update: the into-SSA pass that follows builds the
// barrier's virtual operands like any other statement's.
//
// A pin is not a repair. A zero-fill memset is also what a model writes to
// clear a buffer BEFORE it fills it; pinning that one leaves the real wipe --
// often a loop of stores, which this pass cannot see -- exactly as removable as
// it was. So every recorded site carries `followedByUse`, computed on GIMPLE as
// the contract's section 4 says, and a pinned site with a later use prints the
// "partial" line.
//
// (Unlike clang, GCC lowers `= {0}` to an aggregate assignment `key = {}`, not
// to a memset call, so an initialiser is not a site here at all; see the
// `initloop` shape in the fixture loop.)

#include "Canon.h"
#include "Config.h"

// Standard headers before GCC's: system.h poisons a few identifiers, and a
// standard header included after it may use one.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <set>
#include <string>
#include <vector>

#include "gcc-plugin.h"
#include "plugin-version.h"

#include "tree.h"
#include "tree-pass.h"
#include "context.h"
#include "function.h"
#include "basic-block.h"
#include "gimple.h"
#include "gimple-iterator.h"
#include "gimple-walk.h"
#include "gimplify.h"
#include "tree-cfg.h"
#include "langhooks.h"
#include "options.h"

// GCC loads a plugin only if it defines this symbol: the declaration that the
// plugin's licence is compatible with the GPL, under which GCC is distributed
// and whose headers this file is compiled against. compiler/ is Apache-2.0
// WITH LLVM-exception (compiler/LICENSE), which is GPLv3-compatible; declaring
// it was approved for this component and is required of every GCC plugin.
int plugin_is_GPL_compatible;

namespace wpg {

namespace {

/// `followedByUse`, as a tri-state: the record's true / false / null.
enum class LaterUse { Yes, No, NotLocal };

struct Site {
  int64_t Index = 0;
  bool HaveLength = false;
  int64_t LengthBytes = 0;
  std::string DestKind;
  bool AlreadyVolatile = false;
  bool HaveLine = false;
  int64_t Line = 0;
  LaterUse FollowedByUse = LaterUse::NotLocal;
};

/// One function body that reached the pass. Only plain data is kept: the pass
/// runs during lowering and the record is written at the end of the unit, and
/// between the two GCC's garbage collector runs; a `tree` held here across
/// that gap would be a pointer nobody is keeping alive.
struct FunctionSeen {
  std::string Name;
  unsigned Uid = 0; // DECL_UID: creation order, used to order module scope
  std::string Linkage;
  bool Exact = false;
  bool InScope = false;
  std::vector<Site> Sites;
};

struct Unhandled {
  int64_t LibcallMemset = 0;
  int64_t MemsetChk = 0;
  int64_t NonZeroFill = 0;
  // atomicMemset and inlineWrapperMemset name LLVM shapes that GCC does not
  // have (an element-wise atomic memset intrinsic; clang's `memset.inline`
  // rename of a gnu_inline wrapper). They are written as 0 on every record, as
  // the contract's section 8 fixes, and README.md says so.
};

struct State {
  Config Cfg;
  int64_t Speedup = 0;
  int64_t Size = 0;
  std::vector<FunctionSeen> Functions;
  /// Names of functions referenced from any body that reached the pass --
  /// called, or with their address taken. The GCC reading of "declared in the
  /// module": clang puts a declaration in the module for exactly the functions
  /// the unit references.
  std::set<std::string> Referenced;
  Unhandled U;
  int64_t ZeroFillInScope = 0;
  int64_t ZeroFillInModule = 0;
  int64_t WouldPin = 0;
  int64_t Pinned = 0;
  /// Eligible sites where no barrier could be placed (see insertPin). Zero in
  /// every compile measured; printed, and visible as pinnedCount <
  /// wouldPinCount, if it ever is not.
  int64_t NotPlaced = 0;
  unsigned UnitsFinished = 0;
};

/// Allocated only when the plugin installs. Never freed: it lives exactly as
/// long as the compiler process, like the pass object GCC owns.
State *G = nullptr;

// ------------------------------------------------------------------ names --

std::string stripEncoding(const char *S) {
  // GCC marks a name that must be written verbatim (an `asm("label")`) with a
  // leading '*'. The symbol is what follows.
  if (S && S[0] == '*') ++S;
  return S ? std::string(S) : std::string();
}

/// The name a requested function is matched against: the assembler name,
/// which is what clang's Module::getFunction is keyed by. For C it is the
/// declared name. Computing it for a body that reached the pass is what
/// emitting that body does anyway.
std::string symbolNameOf(tree FnDecl) {
  return stripEncoding(IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(FnDecl)));
}

/// The same name for a function that is only referenced, WITHOUT computing an
/// assembler name that nobody asked for yet: the assembler name if GCC has set
/// one, the declared name otherwise. For C the two are the same string.
std::string referencedNameOf(tree FnDecl) {
  if (DECL_ASSEMBLER_NAME_SET_P(FnDecl))
    return stripEncoding(IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME_RAW(FnDecl)));
  if (DECL_NAME(FnDecl)) return IDENTIFIER_POINTER(DECL_NAME(FnDecl));
  return std::string();
}

/// The contract's section 6: LLVM's spelling of the linkage, so the reader and
/// the rows need no second vocabulary. See README.md for why DECL_COMDAT is
/// tested before DECL_WEAK.
const char *linkageOf(tree FnDecl) {
  if (!TREE_PUBLIC(FnDecl)) return "internal";
  if (DECL_COMDAT(FnDecl)) return "linkonce_odr";
  if (DECL_WEAK(FnDecl)) return "weak";
  // The body reached this pass, so an external declaration here is one with a
  // body: a gnu_inline / C99 inline definition, never emitted by this unit.
  if (DECL_EXTERNAL(FnDecl)) return "available_externally";
  return "external";
}

// ------------------------------------------------------------- operands --

tree mentionCb(tree *Tp, int *WalkSubtrees, void *Data) {
  auto *Wi = static_cast<walk_stmt_info *>(Data);
  const auto *Set = static_cast<const std::set<tree> *>(Wi->info);
  if (Set->count(*Tp)) return *Tp;
  // A type can carry an expression (a VLA bound); that is not a use.
  if (TYPE_P(*Tp)) *WalkSubtrees = 0;
  return NULL_TREE;
}

/// Whether any operand of `Stmt`, at any depth, is one of `Set`. `&key`
/// contains `key`, so taking the address counts.
bool mentions(gimple *Stmt, const std::set<tree> &Set) {
  walk_stmt_info Wi;
  std::memset(&Wi, 0, sizeof Wi);
  Wi.info = const_cast<std::set<tree> *>(&Set);
  return walk_gimple_op(Stmt, mentionCb, &Wi) != NULL_TREE;
}

tree referenceCb(tree *Tp, int *WalkSubtrees, void *Data) {
  auto *Wi = static_cast<walk_stmt_info *>(Data);
  auto *Names = static_cast<std::set<std::string> *>(Wi->info);
  if (TREE_CODE(*Tp) == FUNCTION_DECL) {
    const std::string N = referencedNameOf(*Tp);
    if (!N.empty()) Names->insert(N);
  }
  if (TYPE_P(*Tp)) *WalkSubtrees = 0;
  return NULL_TREE;
}

void noteReferencedFunctions(gimple *Stmt, std::set<std::string> &Names) {
  walk_stmt_info Wi;
  std::memset(&Wi, 0, sizeof Wi);
  Wi.info = &Names;
  walk_gimple_op(Stmt, referenceCb, &Wi);
}

// ----------------------------------------------------------- destination --

struct Dest {
  const char *Kind;
  /// The automatic VAR_DECL the memset writes, when Kind is "alloca".
  tree Local;
};

/// The observer's classifyTarget words (the contract's section 5): a local
/// automatic VAR_DECL is `alloca`, a PARM_DECL (or a pointer that is one) is
/// `argument`, a static or global VAR_DECL is `global`, anything else `other`.
///
/// The destination is followed back through what the gimplifier and the
/// front end put between the object and the call: `&obj`, `&MEM[p + off]`
/// (to p), and SSA temporaries that copy, convert or offset a pointer. A local
/// pointer variable that holds an address (`unsigned char *p = key;
/// memset(p, ...)`) is not followed -- this pass runs before `ssa`, where
/// such a variable is still a VAR_DECL whose value is whatever was last
/// stored -- and reads `other`, as the same shape reads on the LLVM side
/// (a pointer reloaded from a stack slot). A VLA or __builtin_alloca buffer
/// is reached through such a pointer and reads `other` too.
Dest classifyDest(tree T, tree FnDecl) {
  for (int Guard = 0; Guard < 64 && T; ++Guard) {
    STRIP_NOPS(T);
    switch (TREE_CODE(T)) {
    case ADDR_EXPR: {
      tree Base = get_base_address(TREE_OPERAND(T, 0));
      if (!Base) return {"other", NULL_TREE};
      if (TREE_CODE(Base) == MEM_REF || TREE_CODE(Base) == TARGET_MEM_REF) {
        T = TREE_OPERAND(Base, 0);
        continue;
      }
      if (VAR_P(Base)) {
        if (auto_var_in_fn_p(Base, FnDecl)) return {"alloca", Base};
        if (is_global_var(Base)) return {"global", NULL_TREE};
        return {"other", NULL_TREE};
      }
      // An aggregate passed by value, its address taken: LLVM's byval
      // argument, which getUnderlyingObject reports as the Argument.
      if (TREE_CODE(Base) == PARM_DECL) return {"argument", NULL_TREE};
      return {"other", NULL_TREE};
    }
    case PARM_DECL:
      return {"argument", NULL_TREE};
    case SSA_NAME: {
      if (SSA_NAME_IS_DEFAULT_DEF(T)) {
        tree V = SSA_NAME_VAR(T);
        return {V && TREE_CODE(V) == PARM_DECL ? "argument" : "other", NULL_TREE};
      }
      gimple *Def = SSA_NAME_DEF_STMT(T);
      if (!Def || !is_gimple_assign(Def)) return {"other", NULL_TREE};
      const enum tree_code Code = gimple_assign_rhs_code(Def);
      if (Code == POINTER_PLUS_EXPR || CONVERT_EXPR_CODE_P(Code) || Code == SSA_NAME ||
          Code == ADDR_EXPR || Code == PARM_DECL) {
        T = gimple_assign_rhs1(Def);
        continue;
      }
      return {"other", NULL_TREE};
    }
    default:
      return {"other", NULL_TREE};
    }
  }
  return {"other", NULL_TREE};
}

// ---------------------------------------------------------- followedByUse --

/// Everything that holds the buffer's address in this function: the VAR_DECL
/// itself, and -- to a fixed point -- every SSA name or local pointer variable
/// assigned (or returned from a call) by a statement that mentions something
/// already in the set. That is the GCC reading of what WipePin does with stack
/// slots: `unsigned char *p = key; memset(key, ...); derive(p);` reads `true`
/// because `derive(p)` mentions p and p holds &key. An address stored into
/// anything that is not a pointer-typed local -- a global, a struct field, an
/// array element, the heap, a callee's memory -- is not followed, and a use
/// made through it is missed. A pointer-typed local that is later given
/// another value keeps counting: that errs towards "yes".
std::set<tree> carriersOf(tree Decl, function *Fun) {
  std::set<tree> C{Decl};
  bool Changed = true;
  while (Changed) {
    Changed = false;
    basic_block BB;
    FOR_EACH_BB_FN(BB, Fun) {
      for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
        gimple *Stmt = gsi_stmt(Gsi);
        if (is_gimple_debug(Stmt) || gimple_clobber_p(Stmt)) continue;
        if (!is_gimple_assign(Stmt) && !is_gimple_call(Stmt)) continue;
        tree Lhs = gimple_get_lhs(Stmt);
        if (!Lhs || C.count(Lhs) || !POINTER_TYPE_P(TREE_TYPE(Lhs))) continue;
        if (TREE_CODE(Lhs) != SSA_NAME && !(VAR_P(Lhs) && auto_var_in_fn_p(Lhs, Fun->decl)))
          continue;
        if (mentions(Stmt, C)) {
          C.insert(Lhs);
          Changed = true;
        }
      }
    }
  }
  return C;
}

/// The contract's section 4, on GIMPLE: whether some statement other than
/// `Site` that mentions the buffer (or a carrier of its address) can run after
/// `Site`. Breadth-first over basic blocks from the memset: the rest of its
/// own block, then every block reachable along any successor edge (EH and
/// abnormal edges included), each scanned whole -- so a loop back into the
/// memset's own block scans the statements before it too. Clobbers
/// (`key ={v} {CLOBBER}`), debug statements and the memset itself are not
/// uses; another memset into the same buffer is, and so is a barrier asm that
/// names it.
///
/// Reachability is the CFG's, with no path feasibility at all: a path the
/// program can never take still counts. That can add a partial line; it can
/// never remove one. Computed during lowering, on the body as the front end
/// wrote it, before any pin of this function is placed.
LaterUse laterUseOf(gcall *Site, const std::set<tree> &C, function *Fun) {
  auto IsUse = [&](gimple *S) {
    return S != Site && !is_gimple_debug(S) && !gimple_clobber_p(S) && mentions(S, C);
  };
  basic_block Start = gimple_bb(Site);
  gimple_stmt_iterator Gsi = gsi_for_stmt(Site);
  for (gsi_next(&Gsi); !gsi_end_p(Gsi); gsi_next(&Gsi))
    if (IsUse(gsi_stmt(Gsi))) return LaterUse::Yes;

  std::vector<basic_block> Work;
  std::set<int> Visited;
  edge E;
  edge_iterator Ei;
  FOR_EACH_EDGE(E, Ei, Start->succs) Work.push_back(E->dest);
  while (!Work.empty()) {
    basic_block BB = Work.back();
    Work.pop_back();
    if (BB == EXIT_BLOCK_PTR_FOR_FN(Fun) || !Visited.insert(BB->index).second) continue;
    // No PHI nodes to scan: this runs before `ssa`.
    for (gimple_stmt_iterator G2 = gsi_start_bb(BB); !gsi_end_p(G2); gsi_next(&G2))
      if (IsUse(gsi_stmt(G2))) return LaterUse::Yes;
    FOR_EACH_EDGE(E, Ei, BB->succs) Work.push_back(E->dest);
  }
  return LaterUse::No;
}

// ------------------------------------------------------------------- pin --

/// True when the statement after `Site` in its block is already a volatile
/// asm with a "memory" clobber: a pin placed earlier, or a barrier the source
/// wrote itself. Such a site is recorded (`alreadyVolatile: true`) and left
/// alone, as WipePin leaves an already-volatile llvm.memset alone.
bool alreadyPinned(gcall *Site) {
  gimple_stmt_iterator Gsi = gsi_for_stmt(Site);
  gsi_next_nondebug(&Gsi);
  if (gsi_end_p(Gsi)) return false;
  gasm *A = dyn_cast<gasm *>(gsi_stmt(Gsi));
  if (!A || !gimple_asm_volatile_p(A)) return false;
  for (unsigned I = 0; I < gimple_asm_nclobbers(A); ++I) {
    tree C = TREE_VALUE(gimple_asm_clobber_op(A, I));
    if (C && TREE_CODE(C) == STRING_CST && std::strcmp(TREE_STRING_POINTER(C), "memory") == 0)
      return true;
  }
  return false;
}

/// `__asm__ __volatile__("" : : "g"(dest) : "memory")`, as the C front end
/// would have built it from that source line: one input whose constraint is
/// "g", one clobber "memory", no outputs, no labels. The operand is a copy of
/// the memset's own first argument, which is already a GIMPLE value.
gasm *buildPin(gcall *Site) {
  vec<tree, va_gc> *Inputs = nullptr;
  vec<tree, va_gc> *Clobbers = nullptr;
  // Lengths include the terminating NUL, as the lexer's string constants do.
  tree Constraint = build_string(2, "g");
  vec_safe_push(Inputs, build_tree_list(build_tree_list(NULL_TREE, Constraint),
                                        unshare_expr(gimple_call_arg(Site, 0))));
  vec_safe_push(Clobbers, build_tree_list(NULL_TREE, build_string(7, "memory")));
  gasm *A = gimple_build_asm_vec("", Inputs, nullptr, Clobbers, nullptr);
  gimple_asm_set_volatile(A, true);
  gimple_set_location(A, gimple_location(Site));
  return A;
}

/// Places the barrier directly after `Site`. A memset call that ends its basic
/// block (it could only if it could throw, and __builtin_memset is nothrow)
/// gets the barrier at the start of its fallthrough successor instead; with no
/// fallthrough edge there is nowhere "directly after" and nothing is placed.
bool insertPin(gcall *Site) {
  gasm *A = buildPin(Site);
  if (!stmt_ends_bb_p(Site)) {
    gimple_stmt_iterator Gsi = gsi_for_stmt(Site);
    gsi_insert_after(&Gsi, A, GSI_SAME_STMT);
    return true;
  }
  edge E = find_fallthru_edge(gimple_bb(Site)->succs);
  if (!E) return false;
  gsi_insert_on_edge_immediate(E, A);
  return true;
}

// ------------------------------------------------------------------ pass --

const pass_data WipePinPassData = {
    GIMPLE_PASS,
    "wipe_pin",    // -fdump-passes prints it as tree-wipe_pin
    OPTGROUP_NONE,
    TV_NONE,
    PROP_cfg,      // properties_required: registered after `cfg`
    0,             // properties_provided
    0,             // properties_destroyed
    0,             // todo_flags_start
    0,             // todo_flags_finish
};

class WipePinPass : public gimple_opt_pass {
public:
  explicit WipePinPass(gcc::context *Ctxt) : gimple_opt_pass(WipePinPassData, Ctxt) {}

  // Every function, at every level. A pin that silently did not happen at -O0
  // would be a record saying one thing and an object saying another.
  bool gate(function *) final override { return true; }

  unsigned int execute(function *Fun) final override;
};

unsigned int WipePinPass::execute(function *Fun) {
  State &S = *G;
  tree FnDecl = Fun->decl;

  FunctionSeen F;
  F.Name = symbolNameOf(FnDecl);
  F.Uid = DECL_UID(FnDecl);
  F.Linkage = linkageOf(FnDecl);
  F.Exact = F.Linkage == "external" || F.Linkage == "internal";
  F.InScope = S.Cfg.S == Scope::Module ||
              std::find(S.Cfg.Requested.begin(), S.Cfg.Requested.end(), F.Name) !=
                  S.Cfg.Requested.end();

  // --- the census: every site read before anything in this body changes ----
  std::vector<gcall *> ToPin;
  std::vector<std::pair<tree, std::set<tree>>> CarrierCache;
  int64_t Ordinal = 0;
  basic_block BB;
  FOR_EACH_BB_FN(BB, Fun) {
    for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
      gimple *Stmt = gsi_stmt(Gsi);
      noteReferencedFunctions(Stmt, S.Referenced);
      gcall *Call = dyn_cast<gcall *>(Stmt);
      if (!Call) continue;

      if (gimple_call_builtin_p(Call, BUILT_IN_MEMSET)) {
        if (!integer_zerop(gimple_call_arg(Call, 1))) {
          if (F.InScope) S.U.NonZeroFill++;
          continue;
        }
        S.ZeroFillInModule++;
        if (!F.InScope) continue;
        S.ZeroFillInScope++;

        Site St;
        St.Index = Ordinal++;
        tree Len = gimple_call_arg(Call, 2);
        if (TREE_CODE(Len) == INTEGER_CST && tree_fits_shwi_p(Len) &&
            isSafeInteger(tree_to_shwi(Len)) && tree_to_shwi(Len) >= 0) {
          St.HaveLength = true;
          St.LengthBytes = tree_to_shwi(Len);
        }
        const Dest D = classifyDest(gimple_call_arg(Call, 0), FnDecl);
        St.DestKind = D.Kind;
        if (D.Local) {
          const std::set<tree> *C = nullptr;
          for (const auto &Entry : CarrierCache)
            if (Entry.first == D.Local) C = &Entry.second;
          if (!C) {
            CarrierCache.emplace_back(D.Local, carriersOf(D.Local, Fun));
            C = &CarrierCache.back().second;
          }
          St.FollowedByUse = laterUseOf(Call, *C, Fun);
        }
        // GCC keeps a location on every statement, with or without -g; the
        // LLVM twin reads a line only from debug info.
        const location_t Loc = gimple_location(Call);
        if (Loc != UNKNOWN_LOCATION && LOCATION_LINE(Loc) > 0) {
          St.HaveLine = true;
          St.Line = LOCATION_LINE(Loc);
        }
        if (alreadyPinned(Call)) {
          St.AlreadyVolatile = true;
        } else {
          S.WouldPin++;
          ToPin.push_back(Call);
        }
        F.Sites.push_back(std::move(St));
        continue;
      }

      // Wipes this pass does not touch, counted so that "nothing was pinned"
      // can be told apart from "there was nothing to pin".
      if (!F.InScope) continue;
      if (gimple_call_builtin_p(Call, BUILT_IN_MEMSET_CHK)) {
        S.U.MemsetChk++;
        continue;
      }
      tree Callee = gimple_call_fndecl(Call);
      if (Callee && DECL_NAME(Callee)) {
        const char *N = IDENTIFIER_POINTER(DECL_NAME(Callee));
        if (std::strcmp(N, "memset") == 0) S.U.LibcallMemset++;
        else if (std::strcmp(N, "__memset_chk") == 0) S.U.MemsetChk++;
      }
    }
  }

  // --- the pin ---------------------------------------------------------------
  if (!S.Cfg.DryRun) {
    for (gcall *Call : ToPin) {
      if (insertPin(Call)) {
        S.Pinned++;
      } else {
        S.NotPlaced++;
        fprintf(stderr,
                "WipePinGcc: could not place a pin after a zero-fill memset in %s "
                "(the call ends its block and has no fallthrough edge); it is not "
                "counted as pinned\n",
                F.Name.c_str());
      }
    }
  }

  S.Functions.push_back(std::move(F));
  return 0;
}

// ---------------------------------------------------------------- record --

/// interfaces.md section 5's toolchain block, built as the contract's section
/// 3 says: `gcc` is the version of the plugin headers this file was compiled
/// against (plugin-version.h's basever), `packages` names gcc at that version,
/// and `digest` is the SHA-256 of the canonical serialisation of {gcc,
/// packages}. The same construction WipePin uses with `clang`. Nothing from the
/// environment.
Json toolchainJson() {
  auto Pkgs = [] {
    return Json::array().push(Json::object()
                                  .set("name", Json::str("gcc"))
                                  .set("version", Json::str(gcc_version.basever)));
  };
  Json ForDigest = Json::object();
  ForDigest.set("gcc", Json::str(gcc_version.basever));
  ForDigest.set("packages", Pkgs());
  Json T = Json::object();
  T.set("gcc", Json::str(gcc_version.basever));
  T.set("packages", Pkgs());
  T.set("digest", Json::str(sha256Hex(ForDigest.serialise())));
  return T;
}

const char *resolutionWordFor(const State &S, const std::string &Name,
                              const FunctionSeen **Found) {
  *Found = nullptr;
  for (const FunctionSeen &F : S.Functions)
    if (F.Name == Name) {
      *Found = &F;
      return "resolved";
    }
  if (S.Referenced.count(Name)) return "declaration-only";
  return "not-in-module";
}

void finishUnit(void *, void *) {
  State &S = *G;
  const char *Main = main_input_filename ? main_input_filename : "";
  const std::string ModuleName = lbasename(Main);

  if (++S.UnitsFinished > 1)
    fprintf(stderr,
            "WipePinGcc: a second module (%s) reached this pass in one process; the "
            "record at WPIN_OUT is overwritten and describes this module only\n",
            ModuleName.c_str());

  const Config &C = S.Cfg;

  // --- which functions are in scope, and did the names exist -------------
  std::vector<const FunctionSeen *> InScope;
  Json ResolutionJ = Json::array();
  Json RequestedJ = Json::array();
  if (C.S == Scope::Functions) {
    for (const std::string &N : C.Requested) {
      RequestedJ.push(Json::str(N));
      const FunctionSeen *F = nullptr;
      const char *Word = resolutionWordFor(S, N, &F);
      Json Entry = Json::object().set("name", Json::str(N)).set("resolution", Json::str(Word));
      if (F) {
        Entry.set("exact", Json::boolean(F->Exact));
        Entry.set("linkage", Json::str(F->Linkage));
        if (!F->Exact)
          fprintf(stderr,
                  "WipePinGcc: target %s is not an exact definition (%s); the copy that "
                  "runs may come from another translation unit\n",
                  N.c_str(), F->Linkage.c_str());
        InScope.push_back(F);
      } else {
        Entry.set("exact", Json::null());
        Entry.set("linkage", Json::null());
        fprintf(stderr, "WipePinGcc: target %s %s\n", N.c_str(), Word);
      }
      ResolutionJ.push(std::move(Entry));
    }
  } else {
    for (const FunctionSeen &F : S.Functions) InScope.push_back(&F);
    // Creation order of the declarations, which for a C unit is the order the
    // functions were first declared. The order the lowering queue reached them
    // in is deterministic too, but is the call graph's, not the file's.
    std::stable_sort(InScope.begin(), InScope.end(),
                     [](const FunctionSeen *A, const FunctionSeen *B) { return A->Uid < B->Uid; });
  }

  const std::string UnhandledText =
      "libcallMemset=" + std::to_string(S.U.LibcallMemset) +
      " memsetChk=" + std::to_string(S.U.MemsetChk) +
      " nonZeroFill=" + std::to_string(S.U.NonZeroFill) +
      " atomicMemset=0 inlineWrapperMemset=0";
  const bool AnyUnhandled = S.U.LibcallMemset > 0 || S.U.MemsetChk > 0 || S.U.NonZeroFill > 0;
  int64_t FollowedByUse = 0;
  for (const FunctionSeen *F : InScope)
    for (const Site &St : F->Sites)
      if (St.FollowedByUse == LaterUse::Yes) FollowedByUse++;

  if (C.DryRun && S.WouldPin > 0)
    fprintf(stderr,
            "WipePinGcc: dry run: %lld zero-fill memset site(s) would be pinned; none "
            "was changed\n",
            static_cast<long long>(S.WouldPin));
  if (S.WouldPin == 0 && S.ZeroFillInScope == 0)
    fprintf(stderr,
            "WipePinGcc: nothing to pin in scope in %s (zero-fill memset in scope: 0; "
            "unhandled in scope: %s)\n",
            ModuleName.c_str(), UnhandledText.c_str());
  // The partial repair, exactly as WipePin prints it: a recorded site followed
  // by a later use of its buffer, or something pinned while a memset-shaped
  // call in the same scope was left alone.
  if (FollowedByUse > 0 || (S.Pinned > 0 && AnyUnhandled))
    fprintf(stderr,
            "WipePinGcc: partial: pinned %lld site(s) in %s; %lld followed by a later use "
            "of the same buffer (initialiser-like, not a wipe); unhandled in scope: %s\n",
            static_cast<long long>(S.Pinned), ModuleName.c_str(),
            static_cast<long long>(FollowedByUse), UnhandledText.c_str());

  // --- the record --------------------------------------------------------------
  Json R = Json::object();
  R.set("schemaVersion", Json::str("wipe-pin-v2"));
  R.set("component", Json::str("WipePinGcc"));
  R.set("module", Json::str(ModuleName));
  R.set("toolchain", toolchainJson());
  R.set("optLevel", Json::object()
                        .set("speedup", Json::integer(S.Speedup))
                        .set("size", Json::integer(S.Size)));
  R.set("scope", Json::str(C.S == Scope::Functions ? "functions" : "module"));
  R.set("requested", std::move(RequestedJ));
  R.set("resolution", std::move(ResolutionJ));
  R.set("dryRun", Json::boolean(C.DryRun));

  Json P = Json::array();
  for (const FunctionSeen *F : InScope) {
    for (const Site &St : F->Sites) {
      P.push(Json::object()
                 .set("function", Json::str(F->Name))
                 .set("index", Json::integer(St.Index))
                 .set("lengthBytes", St.HaveLength ? Json::integer(St.LengthBytes) : Json::null())
                 .set("destKind", Json::str(St.DestKind))
                 .set("alreadyVolatile", Json::boolean(St.AlreadyVolatile))
                 .set("followedByUse", St.FollowedByUse == LaterUse::NotLocal
                                           ? Json::null()
                                           : Json::boolean(St.FollowedByUse == LaterUse::Yes))
                 .set("line", St.HaveLine ? Json::integer(St.Line) : Json::null()));
    }
  }
  R.set("pinned", std::move(P));
  R.set("pinnedCount", Json::integer(S.Pinned));
  R.set("wouldPinCount", Json::integer(S.WouldPin));
  R.set("seen", Json::object()
                    .set("zeroFillMemsetInScope", Json::integer(S.ZeroFillInScope))
                    .set("zeroFillMemsetInModule", Json::integer(S.ZeroFillInModule)));
  R.set("unhandled", Json::object()
                         .set("libcallMemset", Json::integer(S.U.LibcallMemset))
                         .set("memsetChk", Json::integer(S.U.MemsetChk))
                         .set("nonZeroFill", Json::integer(S.U.NonZeroFill))
                         .set("atomicMemset", Json::integer(0))
                         .set("inlineWrapperMemset", Json::integer(0)));

  // interfaces.md section 5: the digest covers everything but `context`, and
  // `context` holds the one thing a re-run cannot reproduce.
  R.set("evidenceDigest", Json::str(Json::digestOf(R)));
  Json Ctx = Json::object();
  const char *SDE = std::getenv("SOURCE_DATE_EPOCH");
  const int64_t When = SDE ? static_cast<int64_t>(std::strtoll(SDE, nullptr, 10))
                           : static_cast<int64_t>(std::time(nullptr));
  Ctx.set("timeSource", Json::str(SDE ? "SOURCE_DATE_EPOCH" : "wall-clock"));
  Ctx.set("sourceDateEpoch", SDE ? Json::integer(When) : Json::null());
  Ctx.set("generatedAt", Json::integer(When));
  R.set("context", std::move(Ctx));

  std::string Why;
  if (!writeTextFile(C.OutPath, R.serialise() + "\n", Why)) {
    // The bodies have already been changed by the time this runs, so the
    // object carries the pins and there is no record of them. Loud, and
    // pin-gcc.sh turns the missing record into exit 3.
    fprintf(stderr,
            "WipePinGcc: cannot write the record to WPIN_OUT (%s); the IR was %s and "
            "nothing records it\n",
            Why.c_str(), S.Pinned > 0 ? "changed" : "not changed");
  }
}

} // namespace

} // namespace wpg

int plugin_init(struct plugin_name_args *Info, struct plugin_gcc_version *Version) {
  using namespace wpg;

  // First, before any refusal -- before the version check too: clear what an
  // earlier compile left at WPIN_OUT. plugin_init runs when cc1 loads the
  // plugin, which it does even under -fsyntax-only, where no record is ever
  // written; in that compile, and in a refused one, "no record" is then the
  // truth about this compile rather than an old record standing in for it.
  std::string Why;
  if (!clearStaleRecord(Why)) {
    fprintf(stderr, "WipePinGcc: refusing to install: %s\n", Why.c_str());
    return 0;
  }

  // Loud, and not an error, like every refusal here: failing the compile
  // would only get the plugin removed from the build line, and pin-gcc.sh
  // turns "no record" into exit 3 anyway.
  if (!plugin_default_version_check(Version, &gcc_version)) {
    fprintf(stderr,
            "WipePinGcc: refusing to install: built against GCC %s, loaded into GCC %s "
            "(or a differently configured build of it)\n",
            gcc_version.basever, Version && Version->basever ? Version->basever : "?");
    return 0;
  }

  // lto1 reads bodies that cc1 lowered in an earlier process. The lowering
  // passes, and so this pass, never run there; a record written at the end of
  // that unit would describe nothing, and the stale-record rule has already
  // deleted whatever cc1 wrote.
  if (lang_hooks.name && std::strcmp(lang_hooks.name, "GNU GIMPLE") == 0) {
    fprintf(stderr,
            "WipePinGcc: refusing to install: loaded into the LTO back end, where this "
            "pass does not run; load it into the compile step instead\n");
    return 0;
  }

  Config Cfg = loadConfig();
  if (!Cfg.Valid) {
    fprintf(stderr, "WipePinGcc: refusing to install: %s\n", Cfg.Rejected.c_str());
    for (const std::string &N : Cfg.Notes) fprintf(stderr, "%s\n", N.c_str());
    return 0;
  }
  for (const std::string &N : Cfg.Notes) fprintf(stderr, "%s\n", N.c_str());
  if (Info->argc > 0)
    fprintf(stderr,
            "WipePinGcc: %d -fplugin-arg-%s-... argument(s) given and not read; the "
            "configuration is the WPIN_* environment only\n",
            Info->argc, Info->base_name);

  G = new State();
  G->Cfg = std::move(Cfg);
  // The global options as they stand when the plugin loads, after the driver's
  // -O flags have been decoded. README.md has what gcc-13 reports for each.
  G->Speedup = optimize;
  G->Size = optimize_size;

  static struct plugin_info Inf = {
      "wipe-pin-v2",
      "WipePinGcc: configured by WPIN_OUT, WPIN_TARGET_FNS, WPIN_SCOPE, WPIN_DRY_RUN"};
  register_callback(Info->base_name, PLUGIN_INFO, nullptr, &Inf);

  struct register_pass_info PassInfo;
  PassInfo.pass = new WipePinPass(g);
  PassInfo.reference_pass_name = "cfg";
  PassInfo.ref_pass_instance_number = 1;
  PassInfo.pos_op = PASS_POS_INSERT_AFTER;
  register_callback(Info->base_name, PLUGIN_PASS_MANAGER_SETUP, nullptr, &PassInfo);

  register_callback(Info->base_name, PLUGIN_FINISH_UNIT, finishUnit, nullptr);
  return 0;
}
