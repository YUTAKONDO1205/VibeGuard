// WipeWitnessGcc -- the GCC counterpart of ../../src/WipeWitness.cpp: a
// read-only GCC plugin that counts what is left of WipePinGcc's repairs at the
// start and at the end of GCC's GIMPLE pipeline, and writes a wipe-witness-v1
// record that ../../scripts/witness_check.py pairs with WipePinGcc's record.
//
// WipePinGcc (../../../gcc-repair/src/WipePinGcc.cpp) is a GIMPLE pass
// registered directly after `cfg`; every repair it makes is the same barrier,
// `__asm__ __volatile__("" : : "g"(dest) : "memory")` (its buildPin and
// buildPinFor). This plugin registers two GIMPLE passes:
//
//   start  after `*warn_function_return` (instance 1), which in GCC 10 to 14
//          comes after `cfg` and so after `wipe_pin`, whichever plugin was
//          loaded first. GCC initialises plugins in an order the command line
//          does not fix, so the order is made structural instead of relying on
//          the load order as the clang plugin must.
//   end    after `optimized` (instance 1), the last GIMPLE pass before RTL
//          expansion. It runs at -O0 too.
//
// A function the optimiser removed (inlined everywhere, or unreachable) never
// reaches the end pass: it is `absent` at the end. A clone (`.part.N`,
// `.constprop.N`, `.isra.N`) reaches it under its own name, which the start
// pass never saw.
//
// It changes no statement and no declaration; each pass returns 0 (no TODO).
// The record is written once, at PLUGIN_FINISH_UNIT, as WipePinGcc writes its.
//
// What is counted, per function:
//   barriers             a volatile asm with an empty string, one input whose
//                        constraint is "g", no outputs, no labels, and exactly
//                        one clobber, "memory": WipePinGcc's barrier. A barrier
//                        the source wrote in that form is the same GIMPLE and
//                        is counted the same way (README).
//   otherMemoryAsm       any other volatile asm with a "memory" clobber
//   volatileZeroMemsets  always 0: GCC has no volatile memset builtin, and
//                        WipePinGcc's pin is the barrier above
//   volatileZeroStores   a store, not a clobber, with volatile operands whose
//                        stored value is a zero constant

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
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
#include "langhooks.h"
#include "options.h"
#include "pass_manager.h"

int plugin_is_GPL_compatible;

namespace {

const char *const SchemaVersion = "wipe-witness-v1";
const char *const OutVar = "WWIT_OUT";

struct Counts {
  int64_t Barriers = 0;
  int64_t OtherMemoryAsm = 0;
  int64_t VolatileZeroMemsets = 0;
  int64_t VolatileZeroStores = 0;
};

struct Entry {
  std::string Name;
  bool HaveStart = false;
  Counts Start;
  bool HaveEnd = false;
  Counts End;
};

struct State {
  std::string OutPath;
  std::string HostBasever;
  std::string ModuleName;
  int64_t Speedup = 0;
  int64_t Size = 0;
  bool EndRan = false;
  bool OrderKnown = false;
  const char *Order = "no-wipepin";
  std::vector<Entry> Entries;
  std::map<std::string, size_t> Index;
};

State *G = nullptr;

/// The assembler name without GCC's leading '*' (an `asm("label")` name):
/// the name WipePinGcc's record uses (its symbolNameOf).
std::string nameOf(function *Fun) {
  const char *S = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(Fun->decl));
  if (S && S[0] == '*') ++S;
  return S ? std::string(S) : std::string();
}

bool isMemoryClobber(tree C) {
  tree V = TREE_VALUE(C);
  return V && TREE_CODE(V) == STRING_CST &&
         std::strcmp(TREE_STRING_POINTER(V), "memory") == 0;
}

/// WipePinGcc's barrier: volatile, "", one input "g", no outputs, no labels,
/// one clobber "memory".
bool isWipePinBarrier(gasm *A) {
  if (!gimple_asm_volatile_p(A)) return false;
  const char *Str = gimple_asm_string(A);
  if (!Str || Str[0] != '\0') return false;
  if (gimple_asm_ninputs(A) != 1 || gimple_asm_noutputs(A) != 0 ||
      gimple_asm_nlabels(A) != 0 || gimple_asm_nclobbers(A) != 1)
    return false;
  if (!isMemoryClobber(gimple_asm_clobber_op(A, 0))) return false;
  tree Con = TREE_VALUE(TREE_PURPOSE(gimple_asm_input_op(A, 0)));
  return Con && TREE_CODE(Con) == STRING_CST &&
         std::strcmp(TREE_STRING_POINTER(Con), "g") == 0;
}

bool hasMemoryClobber(gasm *A) {
  for (unsigned I = 0; I < gimple_asm_nclobbers(A); ++I)
    if (isMemoryClobber(gimple_asm_clobber_op(A, I))) return true;
  return false;
}

bool isZeroConstant(tree V) {
  if (!V) return false;
  if (TREE_CODE(V) == INTEGER_CST) return integer_zerop(V);
  if (TREE_CODE(V) == REAL_CST) return real_zerop(V);
  if (TREE_CODE(V) == VECTOR_CST || TREE_CODE(V) == CONSTRUCTOR)
    return initializer_zerop(V);
  return false;
}

Counts countIn(function *Fun) {
  Counts C;
  basic_block BB;
  FOR_EACH_BB_FN(BB, Fun) {
    for (gimple_stmt_iterator Gsi = gsi_start_bb(BB); !gsi_end_p(Gsi); gsi_next(&Gsi)) {
      gimple *Stmt = gsi_stmt(Gsi);
      if (gasm *A = dyn_cast<gasm *>(Stmt)) {
        if (isWipePinBarrier(A))
          C.Barriers++;
        else if (gimple_asm_volatile_p(A) && hasMemoryClobber(A))
          C.OtherMemoryAsm++;
        continue;
      }
      if (is_gimple_assign(Stmt) && gimple_store_p(Stmt) && !gimple_clobber_p(Stmt) &&
          gimple_has_volatile_ops(Stmt) && gimple_assign_single_p(Stmt) &&
          isZeroConstant(gimple_assign_rhs1(Stmt)))
        C.VolatileZeroStores++;
    }
  }
  return C;
}

Entry &entryFor(State &S, const std::string &Name) {
  auto It = S.Index.find(Name);
  if (It != S.Index.end()) return S.Entries[It->second];
  S.Index[Name] = S.Entries.size();
  Entry E;
  E.Name = Name;
  S.Entries.push_back(E);
  return S.Entries.back();
}

/// "wipepin-first" when a pass named wipe_pin comes before `Self` in the
/// lowering passes, "witness-first" when after, "no-wipepin" when absent.
const char *orderOf(opt_pass *Self) {
  bool SeenSelf = false;
  for (opt_pass *P = g->get_passes()->all_lowering_passes; P; P = P->next) {
    if (P == Self) {
      SeenSelf = true;
      continue;
    }
    if (P->name && std::strcmp(P->name, "wipe_pin") == 0)
      return SeenSelf ? "witness-first" : "wipepin-first";
  }
  return "no-wipepin";
}

const pass_data StartData = {
    GIMPLE_PASS, "wipe_witness_start", OPTGROUP_NONE, TV_NONE, PROP_cfg, 0, 0, 0, 0,
};
const pass_data EndData = {
    GIMPLE_PASS, "wipe_witness_end", OPTGROUP_NONE, TV_NONE, PROP_cfg, 0, 0, 0, 0,
};

class StartPass : public gimple_opt_pass {
public:
  explicit StartPass(gcc::context *Ctxt) : gimple_opt_pass(StartData, Ctxt) {}
  bool gate(function *) final override { return true; }
  unsigned int execute(function *Fun) final override {
    State &S = *G;
    if (!S.OrderKnown) {
      S.Order = orderOf(this);
      S.OrderKnown = true;
    }
    Entry &E = entryFor(S, nameOf(Fun));
    E.HaveStart = true;
    E.Start = countIn(Fun);
    return 0;
  }
};

class EndPass : public gimple_opt_pass {
public:
  explicit EndPass(gcc::context *Ctxt) : gimple_opt_pass(EndData, Ctxt) {}
  bool gate(function *) final override { return true; }
  unsigned int execute(function *Fun) final override {
    State &S = *G;
    S.EndRan = true;
    Entry &E = entryFor(S, nameOf(Fun));
    E.HaveEnd = true;
    E.End = countIn(Fun);
    return 0;
  }
};

void putString(std::string &O, const std::string &S) {
  static const char *Hex = "0123456789abcdef";
  O.push_back('"');
  for (unsigned char C : S) {
    switch (C) {
    case '"': O += "\\\""; break;
    case '\\': O += "\\\\"; break;
    case '\n': O += "\\n"; break;
    case '\r': O += "\\r"; break;
    case '\t': O += "\\t"; break;
    case '\b': O += "\\b"; break;
    case '\f': O += "\\f"; break;
    default:
      if (C < 0x20) {
        O += "\\u00";
        O.push_back(Hex[(C >> 4) & 0xF]);
        O.push_back(Hex[C & 0xF]);
      } else {
        O.push_back(static_cast<char>(C));
      }
    }
  }
  O.push_back('"');
}

void putCounts(std::string &O, const Counts &C) {
  O += "{\"barriers\":" + std::to_string(C.Barriers) +
       ",\"otherMemoryAsm\":" + std::to_string(C.OtherMemoryAsm) +
       ",\"volatileZeroMemsets\":" + std::to_string(C.VolatileZeroMemsets) +
       ",\"volatileZeroStores\":" + std::to_string(C.VolatileZeroStores) + "}";
}

/// The integer before the first '.' of a basever ("13.3.0" -> 13).
bool majorOf(const char *S, int64_t &Out) {
  if (!S || *S < '0' || *S > '9') return false;
  int64_t V = 0;
  for (; *S >= '0' && *S <= '9'; ++S) V = V < 100000000 ? V * 10 + (*S - '0') : V;
  Out = V;
  return true;
}

void finishUnit(void *, void *) {
  if (!G) return;
  State &S = *G;
  std::string O;
  int64_t IdentMajor = 0, BuiltMajor = 0;
  const bool HaveIdent = majorOf(S.HostBasever.c_str(), IdentMajor);
  majorOf(gcc_version.basever, BuiltMajor);
  O += "{\"schemaVersion\":";
  putString(O, SchemaVersion);
  O += ",\"component\":\"WipeWitnessGcc\",\"module\":";
  putString(O, S.ModuleName);
  O += ",\"ident\":";
  if (S.HostBasever.empty()) O += "null";
  else putString(O, S.HostBasever);
  O += ",\"identMajor\":";
  O += HaveIdent ? std::to_string(IdentMajor) : std::string("null");
  O += ",\"gccMajor\":" + std::to_string(BuiltMajor);
  O += ",\"gccVersion\":";
  putString(O, gcc_version.basever ? gcc_version.basever : "");
  O += ",\"optLevel\":{\"speedup\":" + std::to_string(S.Speedup) +
       ",\"size\":" + std::to_string(S.Size) + "}";
  O += ",\"order\":";
  putString(O, S.Order);
  O += std::string(",\"endReached\":") + (S.EndRan ? "true" : "false");
  O += ",\"functions\":[";
  bool First = true;
  for (const Entry &E : S.Entries) {
    if (!First) O.push_back(',');
    First = false;
    O += "{\"name\":";
    putString(O, E.Name);
    O += ",\"start\":";
    if (E.HaveStart) putCounts(O, E.Start);
    else O += "null";
    O += ",\"end\":";
    if (S.EndRan && E.HaveEnd) putCounts(O, E.End);
    else O += "null";
    O += ",\"endState\":";
    if (!S.EndRan) O += "null";
    else putString(O, E.HaveEnd ? "defined" : "absent");
    O.push_back('}');
  }
  O += "]}\n";
  FILE *F = fopen(S.OutPath.c_str(), "w");
  if (!F) {
    fprintf(stderr, "WipeWitnessGcc: cannot write the record to %s (%s); nothing records "
                    "this compile\n", OutVar, xstrerror(errno));
    return;
  }
  const bool Ok = fwrite(O.data(), 1, O.size(), F) == O.size();
  if (fclose(F) != 0 || !Ok)
    fprintf(stderr, "WipeWitnessGcc: the record at %s may be incomplete\n", OutVar);
}

} // namespace

int plugin_init(struct plugin_name_args *Info, struct plugin_gcc_version *Version) {
  const char *Out = std::getenv(OutVar);
  if (!Out || !*Out) {
    fprintf(stderr, "WipeWitnessGcc: %s is not set; the plugin is loaded and does nothing\n",
            OutVar);
    return 0;
  }
  // A record an earlier compile left at the path must not stand in for this
  // one: removed first, as WipePinGcc removes its own.
  if (remove(Out) != 0 && errno != ENOENT) {
    fprintf(stderr, "WipeWitnessGcc: refusing to install: cannot remove the file at %s (%s)\n",
            OutVar, xstrerror(errno));
    return 0;
  }
  if (!plugin_default_version_check(Version, &gcc_version)) {
    fprintf(stderr,
            "WipeWitnessGcc: refusing to install: built against GCC %s, loaded into GCC %s\n",
            gcc_version.basever, Version && Version->basever ? Version->basever : "?");
    return 0;
  }
  if (lang_hooks.name && std::strcmp(lang_hooks.name, "GNU GIMPLE") == 0) {
    fprintf(stderr, "WipeWitnessGcc: refusing to install: loaded into the LTO back end, "
                    "where the start pass does not run\n");
    return 0;
  }
  G = new State();
  G->OutPath = Out;
  G->HostBasever = Version && Version->basever ? Version->basever : "";
  G->Speedup = optimize;
  G->Size = optimize_size;
  const char *Base = lbasename(main_input_filename ? main_input_filename : "");
  G->ModuleName = Base ? Base : "";

  static struct plugin_info Inf = {"wipe-witness-v1",
                                   "WipeWitnessGcc: configured by WWIT_OUT"};
  register_callback(Info->base_name, PLUGIN_INFO, nullptr, &Inf);

  struct register_pass_info StartInfo;
  StartInfo.pass = new StartPass(g);
  StartInfo.reference_pass_name = "*warn_function_return";
  StartInfo.ref_pass_instance_number = 1;
  StartInfo.pos_op = PASS_POS_INSERT_AFTER;
  register_callback(Info->base_name, PLUGIN_PASS_MANAGER_SETUP, nullptr, &StartInfo);

  struct register_pass_info EndInfo;
  EndInfo.pass = new EndPass(g);
  EndInfo.reference_pass_name = "optimized";
  EndInfo.ref_pass_instance_number = 1;
  EndInfo.pos_op = PASS_POS_INSERT_AFTER;
  register_callback(Info->base_name, PLUGIN_PASS_MANAGER_SETUP, nullptr, &EndInfo);

  register_callback(Info->base_name, PLUGIN_FINISH_UNIT, finishUnit, nullptr);
  return 0;
}
