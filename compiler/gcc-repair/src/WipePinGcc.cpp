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
// barrier is the pin. Both write the `wipe-pin-v3` record, described field by
// field in compiler/schema/wipe-pin.md (section 14 for what v3 adds to v2).
//
// Two switches, both off by default, put the same barrier after shapes that
// are otherwise only counted (compiler/schema/wipe-pin.md sections 14.3-14.5):
// WPIN_BARRIER_CALLS=1 after a zero-fill __builtin___memset_chk and after
// bzero; WPIN_ZERO_COPY=1 after a copy from an all-zero read-only static (the
// aggregate copy the gimplifier makes of a constant-length memcpy, or a
// memcpy / __memcpy_chk call). With both off the pass changes GIMPLE exactly as
// the v2 pass did: the new census only counts.
//
// A third switch, also off by default, puts the barrier at the other end of a
// buffer's life (section 14.6): WPIN_BUFFER_BARRIER=1 places it directly
// before the `buf ={v} {CLOBBER}` of a local buffer that some zero fill writes
// -- a memset, a loop of zero stores, a zero copy -- with `&buf` as its input
// ("buffer barrier", below), unless every zero fill of the buffer is followed
// by a later use in the same lifetime (an initialiser, not a wipe). With it
// off, nothing of it runs.
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
// compiler/schema/wipe-pin.md section 8 says, and a pinned site with a later
// use prints the "partial" line.
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
// WITH LLVM-exception (compiler/LICENSE); the FSF lists the Apache License 2.0
// as compatible with GPLv3. NOTICE and README.md ("Licence") say more.
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

/// A `barrierCalls.sites[]` entry (compiler/schema/wipe-pin.md section 14.4):
/// a zero-fill call that gets a barrier, or would in a dry run.
struct BarrierSite {
  std::string Callee; // the called function's DECL_NAME
  bool HaveLength = false;
  int64_t LengthBytes = 0;
  bool HaveLine = false;
  int64_t Line = 0;
};

/// A `zeroCopy.sites[]` entry (section 14.5): a copy from an all-zero constant
/// that gets a barrier, or would in a dry run.
struct ZeroCopySite {
  std::string Form;   // "aggregate", "builtin" or "call"
  bool HaveCallee = false;
  std::string Callee; // DECL_NAME; absent exactly for the aggregate form
  std::string Source; // the zero constant's DECL_NAME, "" when it has none
  std::string DestKind;
  bool HaveLength = false;
  int64_t LengthBytes = 0;
  bool HaveLine = false;
  int64_t Line = 0;
};

/// A `bufferBarriers.sites[]` entry (section 14.6): one buffer barrier placed
/// (or, in a dry run, that would have been placed). Plain data, for the reason
/// FunctionSeen gives.
struct BufferSite {
  bool HaveBuffer = false;
  std::string Buffer;     // DECL_NAME; the record says null when there is none
  bool HaveBytes = false;
  int64_t Bytes = 0;
  const char *Reason = "memset";   // "memset", "loop-store", "zero-copy"
  const char *Anchor = "clobber";  // "clobber" or "ret"
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
  std::vector<BarrierSite> Barriers;   // in statement order, in scope only
  std::vector<ZeroCopySite> ZeroCopies; // in statement order, in scope only
  std::vector<BufferSite> BufSites;     // section 14.6's order, in scope only
};

/// compiler/schema/wipe-pin.md section 14.3: what the pass leaves alone,
/// counted in the functions in scope only. A call or copy a switch repairs is
/// not counted.
struct Unhandled {
  int64_t LibcallMemset = 0;
  int64_t MemsetChk = 0;
  int64_t NonZeroFill = 0;
  int64_t BzeroCall = 0;
  /// A copy from an all-zero read-only static as the compiler's own operation:
  /// the aggregate copy, or a BUILT_IN_MEMCPY call.
  int64_t ZeroGlobalCopy = 0;
  /// The same as a checked or library call: BUILT_IN_MEMCPY_CHK, or a call of
  /// memcpy / __memcpy_chk that is not the matching builtin.
  int64_t ZeroGlobalCopyCall = 0;
  // atomicMemset, inlineWrapperMemset and inlineWrapperBzero name LLVM shapes
  // that GCC does not have (an element-wise atomic memset intrinsic; clang's
  // `<name>.inline` rename of a gnu_inline wrapper, which GCC keeps under the
  // wrapper's own name). They are written as 0 on every record, as
  // compiler/schema/wipe-pin.md sections 10 and 14.3 say.
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
  /// barrierCalls: barriers placed after a zero-fill call, and the calls that
  /// get one (or would, in a dry run). The second is the length of `sites`.
  int64_t Barriered = 0;
  int64_t WouldBarrier = 0;
  /// zeroCopy: barriers placed after a copy from an all-zero constant, and
  /// the copies that get one (or would, in a dry run).
  int64_t ZeroCopied = 0;
  int64_t WouldZeroCopy = 0;
  /// bufferBarriers: buffer barriers placed, and the barriers found (dry run
  /// included; the length of `sites`); zero fills in scope whose destination
  /// is not a local buffer of the function, which no barrier covers; local
  /// buffers given no barrier because every zero fill of theirs is followed by
  /// a later use (an initialiser, not a wipe).
  int64_t BufBarriered = 0;
  int64_t WouldBufBarrier = 0;
  int64_t BufNotStack = 0;
  int64_t BufInitialiserOnly = 0;
  /// The `basever` of the compiler that loaded the plugin, as plugin_init
  /// received it (host.ident, compiler/schema/wipe-pin.md section 14.7).
  std::string HostBasever;
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

/// compiler/schema/wipe-pin.md section 5: LLVM's spelling of the linkage, so
/// the reader and the rows need no second vocabulary. DECL_COMDAT is tested
/// before DECL_WEAK because a C++ inline function is both (measured; the same
/// section and README.md).
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

/// The observer's classifyTarget words (compiler/schema/wipe-pin.md section
/// 7): a local
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

/// compiler/schema/wipe-pin.md section 8, on GIMPLE: whether some statement
/// other than
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

/// The declaration a pointer-valued operand is the address of -- `&key`,
/// `&key[3]`, `&MEM[&key + 8]`, each through any conversion -- or NULL_TREE
/// when the operand is not the address of a declaration.
tree addressedDecl(tree T) {
  STRIP_NOPS(T);
  if (TREE_CODE(T) != ADDR_EXPR) return NULL_TREE;
  tree Base = get_base_address(TREE_OPERAND(T, 0));
  return Base && DECL_P(Base) ? Base : NULL_TREE;
}

/// Whether the asm input `In` hands the asm the buffer `Dest` (the memset's
/// first argument) points into: the same pointer value, or the address of the
/// same base declaration.
bool inputNamesDest(tree In, tree Dest) {
  if (!In) return false;
  if (operand_equal_p(In, Dest, 0)) return true;
  tree A = addressedDecl(In);
  return A && A == addressedDecl(Dest);
}

/// True when the statement after `Site` in its block is already a pin: a
/// volatile asm with a "memory" clobber that also takes the memset's
/// destination as an input operand (inputNamesDest). That is this pass's own
/// barrier, or one the source wrote in the same form. Such a site is recorded
/// (`alreadyVolatile: true`) and left alone, as WipePin leaves an
/// already-volatile llvm.memset alone.
///
/// The clobber alone is not a pin. It does not make a store to a local
/// observable when the local's address never leaves the function: gcc-13 -O2
/// deletes the zero fill of `uint64_t k` directly before
/// `__asm__ __volatile__("" ::: "memory")` (measured: the `clobonly` shape),
/// and before a barrier whose operand is a different local (`otherbar`). What
/// keeps the memset is the input operand: the buffer's address reaches the asm,
/// which may then read the bytes through it. A site followed by a barrier
/// without that operand is pinned like any other (compiler/schema/wipe-pin.md
/// section 9).
bool alreadyPinned(gcall *Site) {
  gimple_stmt_iterator Gsi = gsi_for_stmt(Site);
  gsi_next_nondebug(&Gsi);
  if (gsi_end_p(Gsi)) return false;
  gasm *A = dyn_cast<gasm *>(gsi_stmt(Gsi));
  if (!A || !gimple_asm_volatile_p(A)) return false;
  bool Clobbers = false;
  for (unsigned I = 0; I < gimple_asm_nclobbers(A) && !Clobbers; ++I) {
    tree C = TREE_VALUE(gimple_asm_clobber_op(A, I));
    Clobbers = C && TREE_CODE(C) == STRING_CST &&
               std::strcmp(TREE_STRING_POINTER(C), "memory") == 0;
  }
  if (!Clobbers) return false;
  tree Dest = gimple_call_arg(Site, 0);
  for (unsigned I = 0; I < gimple_asm_ninputs(A); ++I)
    if (inputNamesDest(TREE_VALUE(gimple_asm_input_op(A, I)), Dest)) return true;
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

// ------------------------------------------------------- census helpers --

/// compiler/schema/wipe-pin.md section 6's rule for a constant length: an
/// INTEGER_CST that fits a signed host integer, is >= 0 and <= 2^53 - 1.
bool constantLength(tree Len, int64_t &Out) {
  if (!Len || TREE_CODE(Len) != INTEGER_CST || !tree_fits_shwi_p(Len)) return false;
  const int64_t V = tree_to_shwi(Len);
  if (V < 0 || !isSafeInteger(V)) return false;
  Out = V;
  return true;
}

/// The statement's source line, which GCC keeps with or without -g.
bool lineOf(gimple *Stmt, int64_t &Out) {
  const location_t Loc = gimple_location(Stmt);
  if (Loc == UNKNOWN_LOCATION || LOCATION_LINE(Loc) <= 0) return false;
  Out = LOCATION_LINE(Loc);
  return true;
}

/// The called function's DECL_NAME (barrierCalls and zeroCopy `callee`). Every
/// call these sites are made of has a declaration with a name -- a builtin, or
/// a function called by name -- so the fallback is never expected to be used;
/// it keeps `callee` a non-empty string if it ever is.
std::string calleeNameOf(gcall *Call) {
  tree Callee = gimple_call_fndecl(Call);
  if (Callee && DECL_NAME(Callee)) return IDENTIFIER_POINTER(DECL_NAME(Callee));
  return "(unnamed)";
}

/// compiler/schema/wipe-pin.md section 7 applied to the left-hand side of an
/// aggregate copy, read without changing anything (section 14.5: the census
/// marks nothing addressable): the base declaration as classifyDest reads the
/// address of one, or, for `*p` / MEM[p + off], the pointer p as classifyDest
/// reads a call's destination.
const char *classifyLhs(tree Lhs, tree FnDecl) {
  tree Base = get_base_address(Lhs);
  if (!Base) return "other";
  if (TREE_CODE(Base) == MEM_REF || TREE_CODE(Base) == TARGET_MEM_REF)
    return classifyDest(TREE_OPERAND(Base, 0), FnDecl).Kind;
  if (VAR_P(Base)) {
    if (auto_var_in_fn_p(Base, FnDecl)) return "alloca";
    if (is_global_var(Base)) return "global";
    return "other";
  }
  if (TREE_CODE(Base) == PARM_DECL) return "argument";
  return "other";
}

// ------------------------------------------------------------- zero copy --

/// A static, read-only variable defined in this unit whose value is all zero
/// (compiler/schema/wipe-pin.md section 14.3, "zero constant"):
/// `static const unsigned char zeros[65536];` (no initializer, so zero) or one
/// initialised with zeros. Not an extern declaration (its value is elsewhere),
/// not a common symbol, not volatile.
bool isZeroConstantDecl(tree D) {
  if (!D || !VAR_P(D) || !TREE_STATIC(D) || !TREE_READONLY(D) ||
      DECL_EXTERNAL(D) || DECL_COMMON(D) || TREE_THIS_VOLATILE(D))
    return false;
  tree Init = DECL_INITIAL(D);
  return Init == NULL_TREE || (Init != error_mark_node && initializer_zerop(Init));
}

/// The zero constant's name for `zeroCopy.sites[].source`; "" when it has none.
std::string declNameOf(tree D) {
  return D && DECL_NAME(D) ? std::string(IDENTIFIER_POINTER(DECL_NAME(D))) : std::string();
}

/// The barrier after a statement that is not a memset call, with `Addr` -- a
/// GIMPLE value holding the destination's address -- as its input. The same
/// asm as buildPin.
gasm *buildPinFor(tree Addr, location_t Loc) {
  vec<tree, va_gc> *Inputs = nullptr;
  vec<tree, va_gc> *Clobbers = nullptr;
  tree Constraint = build_string(2, "g");
  vec_safe_push(Inputs, build_tree_list(build_tree_list(NULL_TREE, Constraint),
                                        unshare_expr(Addr)));
  vec_safe_push(Clobbers, build_tree_list(NULL_TREE, build_string(7, "memory")));
  gasm *A = gimple_build_asm_vec("", Inputs, nullptr, Clobbers, nullptr);
  gimple_asm_set_volatile(A, true);
  gimple_set_location(A, Loc);
  return A;
}

/// The address the barrier takes for an aggregate copy `LHS = <zero const>`:
/// &decl when the destination is (part of) a declaration, the pointer when it
/// is `*p` / MEM[p + off]. NULL_TREE otherwise (nothing is placed). Marking
/// the declaration addressable changes the body, so this runs only when a
/// barrier is placed: after the census, and never in a dry run.
tree destAddressOf(tree Lhs) {
  tree Base = get_base_address(Lhs);
  if (!Base) return NULL_TREE;
  if (TREE_CODE(Base) == MEM_REF || TREE_CODE(Base) == TARGET_MEM_REF) {
    tree P = TREE_OPERAND(Base, 0);
    return is_gimple_val(P) ? P : NULL_TREE;
  }
  if (VAR_P(Base) || TREE_CODE(Base) == PARM_DECL || TREE_CODE(Base) == RESULT_DECL) {
    mark_addressable(Base);
    return build_fold_addr_expr(Base);
  }
  return NULL_TREE;
}

bool insertPinAfterAssign(gimple *Stmt) {
  tree Addr = destAddressOf(gimple_assign_lhs(Stmt));
  if (!Addr) return false;
  gasm *A = buildPinFor(Addr, gimple_location(Stmt));
  if (!stmt_ends_bb_p(Stmt)) {
    gimple_stmt_iterator Gsi = gsi_for_stmt(Stmt);
    gsi_insert_after(&Gsi, A, GSI_SAME_STMT);
    return true;
  }
  edge E = find_fallthru_edge(gimple_bb(Stmt)->succs);
  if (!E) return false;
  gsi_insert_on_edge_immediate(E, A);
  return true;
}

// --------------------------------------------------------- buffer barrier --
//
// The GCC twin of WipePin's buffer barrier (../llvm-repair/src/WipePin.cpp,
// "the buffer barrier"; compiler/schema/wipe-pin.md section 14.6). The pin
// above sits right after a wipe it can see; a wipe written as a loop of stores
// is not a call, and nothing above sees it. The buffer barrier sits at the
// other end: directly before each `buf ={v} {CLOBBER}` the gimplifier wrote at
// the end of the buffer's scope (or before every `return`, when the buffer has
// none -- a volatile local gets none), it places the same asm as buildPin,
// with `&buf` as its input. Every store into the buffer before it may then be
// read, so none is dead. The asm emits no instruction, but it makes the
// buffer live in memory, so every store into it before the barrier is a store
// to memory -- the secret's own as well as the wipe's. A buffer whose every
// zero fill is followed by a later use in the same lifetime has no wipe for the
// barrier to keep; the barrier would only keep the secret's last value in
// memory until the scope ends, so such a buffer gets none.

tree bufferOfPointer(tree T, function *Fun, int Depth);

/// The pre-SSA shape of `unsigned char *p = buf; ... p[i] = 0;`: `p` is still a
/// VAR_DECL. It names the buffer when its address is never taken and every
/// assignment to it is (a conversion or an offset of) the address of the same
/// local buffer. Anything else -- a call result, a parameter, two buffers --
/// and the answer is NULL_TREE.
tree bufferOfSlot(tree V, function *Fun, int Depth) {
  if (Depth > 4 || TREE_ADDRESSABLE(V)) return NULL_TREE;
  tree Found = NULL_TREE;
  basic_block BB;
  FOR_EACH_BB_FN(BB, Fun) {
    for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
      gimple *St = gsi_stmt(Gsi);
      if (is_gimple_debug(St) || gimple_clobber_p(St)) continue;
      if (!is_gimple_assign(St) && !is_gimple_call(St)) continue;
      if (gimple_get_lhs(St) != V) continue;
      if (!is_gimple_assign(St)) return NULL_TREE;
      const enum tree_code Code = gimple_assign_rhs_code(St);
      if (!(Code == POINTER_PLUS_EXPR || CONVERT_EXPR_CODE_P(Code) || Code == SSA_NAME ||
            Code == ADDR_EXPR || Code == VAR_DECL))
        return NULL_TREE;
      tree B = bufferOfPointer(gimple_assign_rhs1(St), Fun, Depth + 1);
      if (!B || (Found && Found != B)) return NULL_TREE;
      Found = B;
    }
  }
  return Found;
}

/// The local buffer of `Fun` a pointer-valued operand points into, or
/// NULL_TREE. Followed: conversions, `&obj`, `&MEM[p + off]` (to p), SSA
/// temporaries that copy, convert or offset a pointer, and a pointer-typed
/// local that bufferOfSlot resolves.
tree bufferOfPointer(tree T, function *Fun, int Depth) {
  for (int Guard = 0; Guard < 64 && T; ++Guard) {
    STRIP_NOPS(T);
    switch (TREE_CODE(T)) {
    case ADDR_EXPR: {
      tree Base = get_base_address(TREE_OPERAND(T, 0));
      if (!Base) return NULL_TREE;
      if (TREE_CODE(Base) == MEM_REF || TREE_CODE(Base) == TARGET_MEM_REF) {
        T = TREE_OPERAND(Base, 0);
        continue;
      }
      return VAR_P(Base) && auto_var_in_fn_p(Base, Fun->decl) ? Base : NULL_TREE;
    }
    case SSA_NAME: {
      if (SSA_NAME_IS_DEFAULT_DEF(T)) return NULL_TREE;
      gimple *Def = SSA_NAME_DEF_STMT(T);
      if (!Def || !is_gimple_assign(Def)) return NULL_TREE;
      const enum tree_code Code = gimple_assign_rhs_code(Def);
      if (Code == POINTER_PLUS_EXPR || CONVERT_EXPR_CODE_P(Code) || Code == SSA_NAME ||
          Code == ADDR_EXPR || Code == VAR_DECL) {
        T = gimple_assign_rhs1(Def);
        continue;
      }
      return NULL_TREE;
    }
    case VAR_DECL:
      if (auto_var_in_fn_p(T, Fun->decl) && POINTER_TYPE_P(TREE_TYPE(T)))
        return bufferOfSlot(T, Fun, Depth);
      return NULL_TREE;
    default:
      return NULL_TREE;
    }
  }
  return NULL_TREE;
}

/// The local buffer a store's left-hand side writes into, or NULL_TREE.
tree bufferOfLvalue(tree Lhs, function *Fun) {
  tree Base = get_base_address(Lhs);
  if (!Base) return NULL_TREE;
  if (VAR_P(Base)) return auto_var_in_fn_p(Base, Fun->decl) ? Base : NULL_TREE;
  if (TREE_CODE(Base) == MEM_REF || TREE_CODE(Base) == TARGET_MEM_REF)
    return bufferOfPointer(TREE_OPERAND(Base, 0), Fun, 0);
  return NULL_TREE;
}

/// The indices of the basic blocks that lie on a cycle of the CFG: the GIMPLE
/// reading, before loop discovery has run, of "inside a loop".
std::set<int> blocksOnCycles(function *Fun) {
  std::set<int> On;
  basic_block BB;
  FOR_EACH_BB_FN(BB, Fun) {
    std::vector<basic_block> Work;
    std::set<int> Seen;
    edge E;
    edge_iterator Ei;
    FOR_EACH_EDGE(E, Ei, BB->succs) Work.push_back(E->dest);
    while (!Work.empty()) {
      basic_block X = Work.back();
      Work.pop_back();
      if (X == BB) {
        On.insert(BB->index);
        break;
      }
      if (X == EXIT_BLOCK_PTR_FOR_FN(Fun) || !Seen.insert(X->index).second) continue;
      FOR_EACH_EDGE(E, Ei, X->succs) Work.push_back(E->dest);
    }
  }
  return On;
}

/// laterUseOf for a buffer barrier's fill, with one difference: a statement
/// that only computes an address of the buffer into a pointer (`_2 = &key +
/// _1`, `p = &key`) is not a use -- the GIMPLE reading of WipePin following a
/// GEP instead of counting it. Without it, every zero store in a loop would
/// read "followed by a use", because the next iteration recomputes its own
/// address.
///
/// With `StopAtLifetimeEnd`, a path that reaches a clobber of the buffer itself
/// (`buf ={v} {CLOBBER}`, the end of its lifetime) is followed no further: a
/// use after it belongs to another lifetime of the buffer. That is what lets a
/// buffer declared in a loop body and wiped at the end of every iteration read
/// as wiped, rather than as an initialiser of the next iteration's fill.
LaterUse bufferLaterUse(gimple *Site, tree Buf, const std::set<tree> &C, function *Fun,
                        bool StopAtLifetimeEnd) {
  auto IsEnd = [&](gimple *St) {
    return StopAtLifetimeEnd && gimple_clobber_p(St) && gimple_assign_lhs(St) == Buf;
  };
  auto IsUse = [&](gimple *St) {
    if (St == Site || is_gimple_debug(St) || gimple_clobber_p(St) || !mentions(St, C))
      return false;
    if (is_gimple_assign(St)) {
      tree Lhs = gimple_assign_lhs(St);
      if (Lhs && Lhs != Buf && C.count(Lhs) && POINTER_TYPE_P(TREE_TYPE(Lhs))) return false;
    }
    return true;
  };
  basic_block Start = gimple_bb(Site);
  gimple_stmt_iterator Gsi = gsi_for_stmt(Site);
  for (gsi_next(&Gsi); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
    if (IsEnd(gsi_stmt(Gsi))) return LaterUse::No;  // the rest of this path is past the end
    if (IsUse(gsi_stmt(Gsi))) return LaterUse::Yes;
  }
  std::vector<basic_block> Work;
  std::set<int> Visited;
  edge E;
  edge_iterator Ei;
  FOR_EACH_EDGE(E, Ei, Start->succs) Work.push_back(E->dest);
  while (!Work.empty()) {
    basic_block BB = Work.back();
    Work.pop_back();
    if (BB == EXIT_BLOCK_PTR_FOR_FN(Fun) || !Visited.insert(BB->index).second) continue;
    bool Ended = false;
    for (gimple_stmt_iterator G2 = gsi_start_bb(BB); !gsi_end_p(G2); gsi_next(&G2)) {
      if (IsEnd(gsi_stmt(G2))) {
        Ended = true;
        break;
      }
      if (IsUse(gsi_stmt(G2))) return LaterUse::Yes;
    }
    if (Ended) continue;
    FOR_EACH_EDGE(E, Ei, BB->succs) Work.push_back(E->dest);
  }
  return LaterUse::No;
}

/// Whether the zero fill `Site` of `Buf` is followed by a later use of the
/// buffer, for the buffer barrier: only when both the scan bounded by the
/// buffer's lifetime and the unbounded one say so. Both over-approximate (no
/// path feasibility), so the conjunction still errs towards "yes". On GIMPLE
/// the bounded scan reads a subset of what the unbounded one reads, so it is
/// the bounded scan's answer; the conjunction is spelled out to stay WipePin's
/// rule, where the two scans differ.
LaterUse bufferFillFollowedByUse(gimple *Site, tree Buf, const std::set<tree> &C, function *Fun) {
  return bufferLaterUse(Site, Buf, C, Fun, true) == LaterUse::Yes &&
                 bufferLaterUse(Site, Buf, C, Fun, false) == LaterUse::Yes
             ? LaterUse::Yes
             : LaterUse::No;
}

/// The pre-SSA reading of "this pointer was computed by pointer arithmetic":
/// a POINTER_PLUS_EXPR, reached through conversions, SSA copies and local
/// pointer variables or parameters (`p = p + 1`, the `*p++ = 0` loop), or the
/// address of an array element or of a MEM_REF at a non-zero offset.
bool pointerIsOffset(tree T, function *Fun, int Depth) {
  if (Depth > 4 || !T) return false;
  STRIP_NOPS(T);
  switch (TREE_CODE(T)) {
  case ADDR_EXPR: {
    tree Op = TREE_OPERAND(T, 0);
    for (; handled_component_p(Op); Op = TREE_OPERAND(Op, 0))
      if (TREE_CODE(Op) == ARRAY_REF || TREE_CODE(Op) == ARRAY_RANGE_REF) return true;
    if (TREE_CODE(Op) == MEM_REF || TREE_CODE(Op) == TARGET_MEM_REF)
      return !integer_zerop(TREE_OPERAND(Op, 1)) || pointerIsOffset(TREE_OPERAND(Op, 0), Fun, Depth + 1);
    return false;
  }
  case SSA_NAME: {
    if (SSA_NAME_IS_DEFAULT_DEF(T)) return false;
    gimple *Def = SSA_NAME_DEF_STMT(T);
    if (!Def || !is_gimple_assign(Def)) return false;
    const enum tree_code Code = gimple_assign_rhs_code(Def);
    if (Code == POINTER_PLUS_EXPR) return true;
    if (CONVERT_EXPR_CODE_P(Code) || Code == SSA_NAME || Code == VAR_DECL || Code == PARM_DECL ||
        Code == ADDR_EXPR)
      return pointerIsOffset(gimple_assign_rhs1(Def), Fun, Depth + 1);
    return false;
  }
  case VAR_DECL:
  case PARM_DECL: {
    if (!auto_var_in_fn_p(T, Fun->decl)) return false;
    basic_block BB;
    FOR_EACH_BB_FN(BB, Fun) {
      for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
        gimple *St = gsi_stmt(Gsi);
        if (!is_gimple_assign(St) || gimple_assign_lhs(St) != T) continue;
        const enum tree_code Code = gimple_assign_rhs_code(St);
        if (Code == POINTER_PLUS_EXPR) return true;
        if ((CONVERT_EXPR_CODE_P(Code) || Code == SSA_NAME || Code == VAR_DECL || Code == PARM_DECL ||
             Code == ADDR_EXPR) &&
            pointerIsOffset(gimple_assign_rhs1(St), Fun, Depth + 1))
          return true;
      }
    }
    return false;
  }
  default:
    return false;
  }
}

/// For a zero store in a loop whose destination is not a local buffer of the
/// function: whether it writes an element of an array -- an index on the way
/// (`g[i]`, `p->buf[i]`), or memory reached by pointer arithmetic (`out[i]`,
/// `*p++`). Only those are counted as zero fills no barrier covers. A store
/// into one scalar -- a global `g = 0`, `*count = 0`, `p->next = 0`, a field
/// `gs.n = 0` -- is not counted, as a store into a local scalar is not.
bool loopStoreWritesArray(tree Lhs, function *Fun) {
  for (tree T = Lhs; handled_component_p(T); T = TREE_OPERAND(T, 0))
    if (TREE_CODE(T) == ARRAY_REF || TREE_CODE(T) == ARRAY_RANGE_REF) return true;
  tree Base = get_base_address(Lhs);
  if (Base && (TREE_CODE(Base) == MEM_REF || TREE_CODE(Base) == TARGET_MEM_REF))
    return !integer_zerop(TREE_OPERAND(Base, 1)) || pointerIsOffset(TREE_OPERAND(Base, 0), Fun, 0);
  return false;
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
  // Nothing in it changes the body (no declaration is marked addressable, no
  // tree is rewritten), so a dry run compiles to exactly the stock output.
  std::vector<gcall *> ToPin;
  std::vector<gcall *> ToBarrier;           // barrierCalls: a barrier after the call
  std::vector<gcall *> ToZeroCopyCall;      // zeroCopy, forms builtin and call
  std::vector<gimple *> ToZeroCopyAssign;   // zeroCopy, form aggregate
  std::vector<std::pair<tree, std::set<tree>>> CarrierCache;
  int64_t Ordinal = 0;
  // A call that a switch repairs: listed, and kept for the pin phase.
  auto NoteBarrier = [&](gcall *Call, unsigned LenArg) {
    BarrierSite B;
    B.Callee = calleeNameOf(Call);
    B.HaveLength = constantLength(gimple_call_arg(Call, LenArg), B.LengthBytes);
    B.HaveLine = lineOf(Call, B.Line);
    F.Barriers.push_back(std::move(B));
    S.WouldBarrier++;
    ToBarrier.push_back(Call);
  };
  basic_block BB;
  FOR_EACH_BB_FN(BB, Fun) {
    for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
      gimple *Stmt = gsi_stmt(Gsi);
      noteReferencedFunctions(Stmt, S.Referenced);
      // A constant-length memcpy from an all-zero read-only static, which the
      // gimplifier has already turned into an aggregate copy
      //   MEM <unsigned char[64]> [&password] = MEM <unsigned char[64]> [&zeros];
      // (measured outside this tree: gcc-13 -O2 -U_FORTIFY_SOURCE). Memory to
      // memory, aggregate: zeroGlobalCopy, or with WPIN_ZERO_COPY=1 form
      // `aggregate` (compiler/schema/wipe-pin.md sections 14.3 and 14.5).
      if (F.InScope && gimple_assign_single_p(Stmt) && !gimple_clobber_p(Stmt)) {
        tree Lhs = gimple_assign_lhs(Stmt);
        tree Src = get_base_address(gimple_assign_rhs1(Stmt));
        if (Lhs && !is_gimple_reg(Lhs) && !is_gimple_reg_type(TREE_TYPE(Lhs)) &&
            isZeroConstantDecl(Src)) {
          if (S.Cfg.ZeroCopy) {
            ZeroCopySite Z;
            Z.Form = "aggregate";
            Z.Source = declNameOf(Src);
            Z.DestKind = classifyLhs(Lhs, FnDecl);
            Z.HaveLength = constantLength(TYPE_SIZE_UNIT(TREE_TYPE(Lhs)), Z.LengthBytes);
            Z.HaveLine = lineOf(Stmt, Z.Line);
            F.ZeroCopies.push_back(std::move(Z));
            S.WouldZeroCopy++;
            ToZeroCopyAssign.push_back(Stmt);
          } else {
            S.U.ZeroGlobalCopy++;
          }
          continue;
        }
      }
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
        St.HaveLength = constantLength(gimple_call_arg(Call, 2), St.LengthBytes);
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
        St.HaveLine = lineOf(Call, St.Line);
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
      // can be told apart from "there was nothing to pin" -- or, with a switch
      // on, wipes it puts a barrier after (compiler/schema/wipe-pin.md 14.3).
      if (!F.InScope) continue;
      if (gimple_call_builtin_p(Call, BUILT_IN_MEMSET_CHK)) {
        // A zero-fill checked memset, the length a constant or not: with
        // WPIN_BARRIER_CALLS=1 a barrier after it (argument 2 is the length).
        if (S.Cfg.BarrierCalls && integer_zerop(gimple_call_arg(Call, 1))) {
          NoteBarrier(Call, 2);
          continue;
        }
        S.U.MemsetChk++;
        continue;
      }
      tree Callee = gimple_call_fndecl(Call);
      const char *CalleeName = (Callee && DECL_NAME(Callee)) ? IDENTIFIER_POINTER(DECL_NAME(Callee)) : nullptr;
      // bzero: the builtin, or a function named bzero (the -D_FORTIFY_SOURCE
      // header's gnu_inline wrapper). With WPIN_BARRIER_CALLS=1 a barrier after
      // it (argument 1 is the length).
      if (gimple_call_builtin_p(Call, BUILT_IN_BZERO) || (CalleeName && std::strcmp(CalleeName, "bzero") == 0)) {
        if (S.Cfg.BarrierCalls && gimple_call_num_args(Call) >= 2) {
          NoteBarrier(Call, 1);
          continue;
        }
        S.U.BzeroCall++;
        continue;
      }
      // memcpy from an all-zero read-only static: the builtin (form builtin,
      // counted in zeroGlobalCopy when off), __builtin___memcpy_chk or a
      // non-builtin memcpy / __memcpy_chk (form call, zeroGlobalCopyCall). The
      // call stays; the barrier after it keeps what it wrote.
      const bool IsMemcpy = gimple_call_builtin_p(Call, BUILT_IN_MEMCPY);
      const bool IsMemcpyChk = gimple_call_builtin_p(Call, BUILT_IN_MEMCPY_CHK);
      if (IsMemcpy || IsMemcpyChk ||
          (CalleeName && (std::strcmp(CalleeName, "memcpy") == 0 ||
                          std::strcmp(CalleeName, "__memcpy_chk") == 0))) {
        tree Src = gimple_call_num_args(Call) >= 3 ? addressedDecl(gimple_call_arg(Call, 1)) : NULL_TREE;
        if (isZeroConstantDecl(Src)) {
          const bool Builtin = IsMemcpy;
          if (S.Cfg.ZeroCopy) {
            ZeroCopySite Z;
            Z.Form = Builtin ? "builtin" : "call";
            Z.HaveCallee = true;
            Z.Callee = calleeNameOf(Call);
            Z.Source = declNameOf(Src);
            Z.DestKind = classifyDest(gimple_call_arg(Call, 0), FnDecl).Kind;
            Z.HaveLength = constantLength(gimple_call_arg(Call, 2), Z.LengthBytes);
            Z.HaveLine = lineOf(Call, Z.Line);
            F.ZeroCopies.push_back(std::move(Z));
            S.WouldZeroCopy++;
            ToZeroCopyCall.push_back(Call);
          } else if (Builtin) {
            S.U.ZeroGlobalCopy++;
          } else {
            S.U.ZeroGlobalCopyCall++;
          }
        }
        continue;
      }
      if (CalleeName) {
        const char *N = CalleeName;
        if (std::strcmp(N, "memset") == 0) S.U.LibcallMemset++;
        else if (std::strcmp(N, "__memset_chk") == 0) S.U.MemsetChk++;
      }
    }
  }

  // --- the buffer census (WPIN_BUFFER_BARRIER, section 14.6) ----------------
  // Read before any barrier of this body is placed (a pin names the buffer and
  // would read as a later use), and, like the census above, without marking
  // anything addressable: a dry run must still compile to the stock output.
  std::vector<std::pair<gimple *, tree>> ToBufBarrier;
  if (S.Cfg.BufferBarrier && F.InScope) {
    const std::set<int> OnCycle = blocksOnCycles(Fun);
    struct Fill {
      gimple *Stmt;
      const char *Reason;
    };
    std::vector<tree> Order;
    std::vector<std::vector<Fill>> Fills;  // parallel to Order
    auto Note = [&](tree Buf, gimple *Stmt, const char *Reason, bool AggregateOnly) {
      if (!Buf) {
        S.BufNotStack++;
        return;
      }
      if (AggregateOnly && !AGGREGATE_TYPE_P(TREE_TYPE(Buf))) return;
      size_t K = 0;
      while (K < Order.size() && Order[K] != Buf) ++K;
      if (K == Order.size()) {
        Order.push_back(Buf);
        Fills.emplace_back();
      }
      Fills[K].push_back({Stmt, Reason});
    };
    FOR_EACH_BB_FN(BB, Fun) {
      const bool InLoop = OnCycle.count(BB->index) != 0;
      for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
        gimple *Stmt = gsi_stmt(Gsi);
        if (is_gimple_debug(Stmt) || gimple_clobber_p(Stmt)) continue;
        if (gcall *Call = dyn_cast<gcall *>(Stmt)) {
          tree Callee = gimple_call_fndecl(Call);
          const char *Nm = (Callee && DECL_NAME(Callee)) ? IDENTIFIER_POINTER(DECL_NAME(Callee)) : nullptr;
          const unsigned N = gimple_call_num_args(Call);
          const bool IsMemset = gimple_call_builtin_p(Call, BUILT_IN_MEMSET) ||
                                gimple_call_builtin_p(Call, BUILT_IN_MEMSET_CHK) ||
                                (Nm && (std::strcmp(Nm, "memset") == 0 || std::strcmp(Nm, "__memset_chk") == 0));
          const bool IsBzero = gimple_call_builtin_p(Call, BUILT_IN_BZERO) || (Nm && std::strcmp(Nm, "bzero") == 0);
          const bool IsMemcpy = gimple_call_builtin_p(Call, BUILT_IN_MEMCPY) ||
                                gimple_call_builtin_p(Call, BUILT_IN_MEMCPY_CHK) ||
                                (Nm && (std::strcmp(Nm, "memcpy") == 0 || std::strcmp(Nm, "__memcpy_chk") == 0));
          if (IsMemset && N >= 3 && integer_zerop(gimple_call_arg(Call, 1)))
            Note(bufferOfPointer(gimple_call_arg(Call, 0), Fun, 0), Stmt, "memset", false);
          else if (IsBzero && N >= 2)
            Note(bufferOfPointer(gimple_call_arg(Call, 0), Fun, 0), Stmt, "memset", false);
          else if (IsMemcpy && N >= 3 && isZeroConstantDecl(addressedDecl(gimple_call_arg(Call, 1))))
            Note(bufferOfPointer(gimple_call_arg(Call, 0), Fun, 0), Stmt, "zero-copy", false);
          continue;
        }
        if (!gimple_assign_single_p(Stmt)) continue;
        tree Lhs = gimple_assign_lhs(Stmt);
        tree Rhs = gimple_assign_rhs1(Stmt);
        if (!Lhs || is_gimple_reg(Lhs)) continue;  // stores to memory only
        if (!is_gimple_reg_type(TREE_TYPE(Lhs)) && isZeroConstantDecl(get_base_address(Rhs))) {
          Note(bufferOfLvalue(Lhs, Fun), Stmt, "zero-copy", false);
          continue;
        }
        // A volatile store is kept already and needs no reader. A store into
        // something that is not a local buffer is counted only when it writes
        // an array element (loopStoreWritesArray): a store into one scalar
        // outside the function is no more a wipe than one into a local scalar.
        if (InLoop && !TREE_THIS_VOLATILE(Lhs) && initializer_zerop(Rhs)) {
          tree Buf = bufferOfLvalue(Lhs, Fun);
          if (!Buf && !loopStoreWritesArray(Lhs, Fun)) continue;
          Note(Buf, Stmt, "loop-store", true);
        }
      }
    }
    for (size_t K = 0; K < Order.size(); ++K) {
      tree Buf = Order[K];
      const std::set<tree> Carriers = carriersOf(Buf, Fun);
      // The fill `reason` names: the first one no later use follows (the
      // wipe). When every fill has a later use, the buffer is an initialiser
      // only, and it gets no barrier: there is no wipe to keep, and the barrier
      // would keep the secret's last value in memory until the scope ends. It
      // is counted on stderr, not listed. Sites, in order: buffers by their
      // first zero fill, then each buffer's anchors in block order.
      const Fill *Rep = nullptr;
      for (const Fill &Fl : Fills[K])
        if (bufferFillFollowedByUse(Fl.Stmt, Buf, Carriers, Fun) != LaterUse::Yes) {
          Rep = &Fl;
          break;
        }
      if (!Rep) {
        S.BufInitialiserOnly++;
        continue;
      }
      std::vector<gimple *> Ends;
      const char *Anchor = "clobber";
      FOR_EACH_BB_FN(BB, Fun) {
        for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi))
          if (gimple_clobber_p(gsi_stmt(Gsi)) && gimple_assign_lhs(gsi_stmt(Gsi)) == Buf)
            Ends.push_back(gsi_stmt(Gsi));
      }
      if (Ends.empty()) {
        Anchor = "ret";
        FOR_EACH_BB_FN(BB, Fun) {
          for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi))
            if (gimple_code(gsi_stmt(Gsi)) == GIMPLE_RETURN) Ends.push_back(gsi_stmt(Gsi));
        }
      }
      BufferSite Bs;
      if (DECL_NAME(Buf)) {
        Bs.HaveBuffer = true;
        Bs.Buffer = IDENTIFIER_POINTER(DECL_NAME(Buf));
      }
      const HOST_WIDE_INT Bytes = int_size_in_bytes(TREE_TYPE(Buf));
      if (Bytes >= 0 && isSafeInteger(static_cast<int64_t>(Bytes))) {
        Bs.HaveBytes = true;
        Bs.Bytes = static_cast<int64_t>(Bytes);
      }
      Bs.Reason = Rep->Reason;
      Bs.Anchor = Anchor;
      for (gimple *At : Ends) {
        F.BufSites.push_back(Bs);
        ToBufBarrier.emplace_back(At, Buf);
        S.WouldBufBarrier++;
      }
    }
  }

  // --- the pin ---------------------------------------------------------------
  // A barrier that cannot be placed leaves the block's done-count below its
  // would-count, which the strict readers refuse (wipe-pin.md 14.4); it is
  // said here as well.
  if (!S.Cfg.DryRun) {
    for (gcall *Call : ToZeroCopyCall) {   // the destination is argument 0
      if (insertPin(Call)) {
        S.ZeroCopied++;
      } else {
        S.NotPlaced++;
        fprintf(stderr,
                "WipePinGcc: could not place a barrier after a copy from an all-zero "
                "constant in %s (the call ends its block and has no fallthrough edge); "
                "it is not counted as repaired\n",
                F.Name.c_str());
      }
    }
    for (gimple *St : ToZeroCopyAssign) {
      if (insertPinAfterAssign(St)) {
        S.ZeroCopied++;
      } else {
        S.NotPlaced++;
        fprintf(stderr,
                "WipePinGcc: could not place a barrier after a copy from an all-zero "
                "constant in %s (no address for its destination, or no fallthrough "
                "edge); it is not counted as repaired\n",
                F.Name.c_str());
      }
    }
    for (gcall *Call : ToBarrier) {   // the destination is argument 0, as for memset
      if (insertPin(Call)) {
        S.Barriered++;
      } else {
        S.NotPlaced++;
        fprintf(stderr,
                "WipePinGcc: could not place a barrier after a zero-fill call in %s "
                "(the call ends its block and has no fallthrough edge); it is not "
                "counted as repaired\n",
                F.Name.c_str());
      }
    }
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
    // The buffer barrier goes directly BEFORE its anchor (the clobber, or the
    // return), so there is always a place for it. Marking the buffer
    // addressable changes the body, which is why it happens here and never in
    // the census or a dry run.
    for (auto &P : ToBufBarrier) {
      mark_addressable(P.second);
      gasm *A = buildPinFor(build_fold_addr_expr(P.second), gimple_location(P.first));
      gimple_stmt_iterator G = gsi_for_stmt(P.first);
      gsi_insert_before(&G, A, GSI_SAME_STMT);
      S.BufBarriered++;
    }
  }

  S.Functions.push_back(std::move(F));
  return 0;
}

// ---------------------------------------------------------------- record --

/// interfaces.md section 5's toolchain block, built as compiler/schema/
/// wipe-pin.md section 3.1 says: `gcc` is the version of the plugin headers
/// this file was compiled
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

/// The decimal integer before the first '.' of a GCC version string ("13.3.0"
/// -> 13): host.identMajor and host.builtMajor (compiler/schema/wipe-pin.md
/// section 14.7). False when the string does not start with digits followed by
/// a '.', or the number is 0 or too long to be a version.
bool majorBeforeDot(const std::string &V, int64_t &Out) {
  size_t I = 0;
  int64_t N = 0;
  while (I < V.size() && V[I] >= '0' && V[I] <= '9') {
    if (I >= 9) return false;
    N = N * 10 + (V[I] - '0');
    ++I;
  }
  if (I == 0 || I >= V.size() || V[I] != '.' || N < 1) return false;
  Out = N;
  return true;
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

  // The nine unhandled counters of compiler/schema/wipe-pin.md section 14.3,
  // in that section's order; three of them are always 0 on GCC.
  const std::string UnhandledText =
      "libcallMemset=" + std::to_string(S.U.LibcallMemset) +
      " memsetChk=" + std::to_string(S.U.MemsetChk) +
      " nonZeroFill=" + std::to_string(S.U.NonZeroFill) +
      " atomicMemset=0 inlineWrapperMemset=0" +
      " bzeroCall=" + std::to_string(S.U.BzeroCall) +
      " inlineWrapperBzero=0" +
      " zeroGlobalCopy=" + std::to_string(S.U.ZeroGlobalCopy) +
      " zeroGlobalCopyCall=" + std::to_string(S.U.ZeroGlobalCopyCall);
  const bool AnyUnhandled = S.U.LibcallMemset > 0 || S.U.MemsetChk > 0 || S.U.NonZeroFill > 0 ||
                            S.U.BzeroCall > 0 || S.U.ZeroGlobalCopy > 0 || S.U.ZeroGlobalCopyCall > 0;
  // Every repair on GCC is the same inserted barrier, after a memset (the pin),
  // after a zero-fill call, after a copy from an all-zero constant, or before
  // the end of a buffer's lifetime; with the three switches off this is
  // pinnedCount. Section 14.8's sum.
  const int64_t Repaired = S.Pinned + S.Barriered + S.ZeroCopied + S.BufBarriered;
  int64_t FollowedByUse = 0;
  for (const FunctionSeen *F : InScope)
    for (const Site &St : F->Sites)
      if (St.FollowedByUse == LaterUse::Yes) FollowedByUse++;

  if (C.DryRun && S.WouldPin > 0)
    fprintf(stderr,
            "WipePinGcc: dry run: %lld zero-fill memset site(s) would be pinned; none "
            "was changed\n",
            static_cast<long long>(S.WouldPin));
  if (C.DryRun && S.WouldBarrier > 0)
    fprintf(stderr,
            "WipePinGcc: dry run: %lld zero-fill call(s) would get a barrier; none was "
            "changed\n",
            static_cast<long long>(S.WouldBarrier));
  if (C.DryRun && S.WouldZeroCopy > 0)
    fprintf(stderr,
            "WipePinGcc: dry run: %lld copy(ies) from an all-zero constant would get a "
            "barrier; none was changed\n",
            static_cast<long long>(S.WouldZeroCopy));
  if (C.DryRun && S.WouldBufBarrier > 0)
    fprintf(stderr,
            "WipePinGcc: dry run: %lld buffer barrier(s) would be placed; none was changed\n",
            static_cast<long long>(S.WouldBufBarrier));
  // The two buffer-barrier lines, worded as WipePin's: zero fills no barrier
  // can cover (not a local buffer, so no clobber here to stand at), and
  // buffers given no barrier because every zero fill is followed by a later
  // use -- read as an initialiser, though a wipe followed by code that touches
  // the buffer, even code the optimiser then removes, is counted there too.
  if (C.BufferBarrier && S.BufNotStack > 0)
    fprintf(stderr,
            "WipePinGcc: buffer barrier: %lld zero fill(s) in scope write memory that is not a "
            "local buffer of the function (an argument, a global, the heap, or a pointer this "
            "pass does not follow); no barrier covers them\n",
            static_cast<long long>(S.BufNotStack));
  if (C.BufferBarrier && S.BufInitialiserOnly > 0)
    fprintf(stderr,
            "WipePinGcc: buffer barrier: %lld buffer(s) not barriered: every zero fill is followed "
            "by a later use (read as an initialiser; a wipe that later code still touches, even "
            "code the optimiser removes, is counted here too)\n",
            static_cast<long long>(S.BufInitialiserOnly));
  if (S.WouldPin == 0 && S.ZeroFillInScope == 0 && S.WouldBarrier == 0 && S.WouldZeroCopy == 0 &&
      S.WouldBufBarrier == 0)
    fprintf(stderr,
            "WipePinGcc: nothing to pin in scope in %s (zero-fill memset in scope: 0; "
            "unhandled in scope: %s)\n",
            ModuleName.c_str(), UnhandledText.c_str());
  // The partial repair, exactly as WipePin prints it: a recorded site followed
  // by a later use of its buffer, or something repaired while a memset-shaped
  // call or a zero copy in the same scope was left alone. <P> counts every
  // barrier this compile inserted.
  if (FollowedByUse > 0 || (Repaired > 0 && AnyUnhandled))
    fprintf(stderr,
            "WipePinGcc: partial: pinned %lld site(s) in %s; %lld followed by a later use "
            "of the same buffer (initialiser-like, not a wipe); unhandled in scope: %s\n",
            static_cast<long long>(Repaired), ModuleName.c_str(),
            static_cast<long long>(FollowedByUse), UnhandledText.c_str());

  // --- the record --------------------------------------------------------------
  Json R = Json::object();
  R.set("schemaVersion", Json::str("wipe-pin-v3"));
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
                         .set("inlineWrapperMemset", Json::integer(0))
                         .set("bzeroCall", Json::integer(S.U.BzeroCall))
                         .set("inlineWrapperBzero", Json::integer(0))
                         .set("zeroGlobalCopy", Json::integer(S.U.ZeroGlobalCopy))
                         .set("zeroGlobalCopyCall", Json::integer(S.U.ZeroGlobalCopyCall)));

  // compiler/schema/wipe-pin.md sections 14.4-14.6: the three blocks are
  // written on every record. A block whose switch is off lists nothing and
  // counts 0; then the census put nothing in its lists either.
  Json BarrierSites = Json::array();
  Json ZeroSites = Json::array();
  for (const FunctionSeen *F : InScope) {
    for (const BarrierSite &B : F->Barriers)
      BarrierSites.push(Json::object()
                            .set("function", Json::str(F->Name))
                            .set("callee", Json::str(B.Callee))
                            .set("lengthBytes", B.HaveLength ? Json::integer(B.LengthBytes) : Json::null())
                            .set("line", B.HaveLine ? Json::integer(B.Line) : Json::null()));
    for (const ZeroCopySite &Z : F->ZeroCopies)
      ZeroSites.push(Json::object()
                         .set("function", Json::str(F->Name))
                         .set("form", Json::str(Z.Form))
                         .set("callee", Z.HaveCallee ? Json::str(Z.Callee) : Json::null())
                         .set("source", Json::str(Z.Source))
                         .set("destKind", Json::str(Z.DestKind))
                         .set("lengthBytes", Z.HaveLength ? Json::integer(Z.LengthBytes) : Json::null())
                         .set("line", Z.HaveLine ? Json::integer(Z.Line) : Json::null()));
  }
  R.set("barrierCalls", Json::object()
                            .set("enabled", Json::boolean(C.BarrierCalls))
                            .set("sites", std::move(BarrierSites))
                            .set("barrierCount", Json::integer(S.Barriered))
                            .set("wouldBarrierCount", Json::integer(S.WouldBarrier)));
  R.set("zeroCopy", Json::object()
                        .set("enabled", Json::boolean(C.ZeroCopy))
                        .set("sites", std::move(ZeroSites))
                        .set("repairedCount", Json::integer(S.ZeroCopied))
                        .set("wouldRepairCount", Json::integer(S.WouldZeroCopy)));
  // Section 14.6. `count` is the barriers placed (0 in a dry run); `sites` has
  // one entry per barrier placed, or that would have been placed in a dry
  // run. With the switch off the census put nothing in BufSites, and the block
  // is {"enabled":false,"count":0,"sites":[]}.
  Json BufSitesJ = Json::array();
  for (const FunctionSeen *F : InScope)
    for (const BufferSite &B : F->BufSites)
      BufSitesJ.push(Json::object()
                         .set("function", Json::str(F->Name))
                         .set("buffer", B.HaveBuffer ? Json::str(B.Buffer) : Json::null())
                         .set("bytes", B.HaveBytes ? Json::integer(B.Bytes) : Json::null())
                         .set("reason", Json::str(B.Reason))
                         .set("anchor", Json::str(B.Anchor)));
  R.set("bufferBarriers", Json::object()
                              .set("enabled", Json::boolean(C.BufferBarrier))
                              .set("count", Json::integer(S.BufBarriered))
                              .set("sites", std::move(BufSitesJ)));

  // Section 14.7, the GCC column: the version of the compiler that loaded the
  // plugin, as plugin_init received it, against the one the plugin was built
  // for. plugin_default_version_check has already compared the two (basever,
  // datestamp, devphase, revision, configuration arguments) and refused on a
  // difference, so `checked` is true on every record.
  int64_t IdentMajor = 0, BuiltMajor = 0;
  const bool HaveIdentMajor = majorBeforeDot(S.HostBasever, IdentMajor);
  const bool HaveBuiltMajor = majorBeforeDot(gcc_version.basever ? gcc_version.basever : "", BuiltMajor);
  R.set("host", Json::object()
                    .set("ident", Json::str(S.HostBasever))
                    .set("identMajor", HaveIdentMajor ? Json::integer(IdentMajor) : Json::null())
                    // Never 0 in practice (basever starts with the major); a 0
                    // here would be refused by the readers, which is the point.
                    .set("builtMajor", Json::integer(HaveBuiltMajor ? BuiltMajor : 0))
                    .set("checked", Json::boolean(true))
                    .set("intrinsicsCompared", Json::null()));

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
            Why.c_str(), Repaired > 0 ? "changed" : "not changed");
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
  // host.ident: the running compiler's basever, which the version check above
  // has just compared with the one this plugin was built against.
  G->HostBasever = Version && Version->basever ? Version->basever : "";

  static struct plugin_info Inf = {
      "wipe-pin-v3",
      "WipePinGcc: configured by WPIN_OUT, WPIN_TARGET_FNS, WPIN_SCOPE, WPIN_DRY_RUN, "
      "WPIN_BARRIER_CALLS, WPIN_ZERO_COPY, WPIN_BUFFER_BARRIER"};
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
