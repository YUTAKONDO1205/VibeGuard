#include "PinSelector.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"

#include <algorithm>
#include <cstdlib>
#include <system_error>

namespace wpin {

namespace {

/// Unset and empty are the same thing here. An exported-but-empty variable is
/// what a shell leaves behind after `WPIN_OUT=$maybe_unset`, and treating it as
/// a path would make the plugin try to write a file called "".
std::string envOrEmpty(const char *Name) {
  const char *V = std::getenv(Name);
  return V ? std::string(V) : std::string();
}

std::string trim(const std::string &S) {
  const char *WS = " \t\r\n";
  const auto B = S.find_first_not_of(WS);
  if (B == std::string::npos) return std::string();
  const auto E = S.find_last_not_of(WS);
  return S.substr(B, E - B + 1);
}

std::vector<std::string> splitCommas(const std::string &S) {
  std::vector<std::string> Out;
  std::string Cur;
  auto Flush = [&] {
    std::string T = trim(Cur);
    if (!T.empty()) Out.push_back(T);
    Cur.clear();
  };
  for (char C : S) {
    if (C == ',') Flush();
    else Cur.push_back(C);
  }
  Flush();
  return Out;
}

} // namespace

Config loadConfig() {
  Config C;

  C.OutPath = envOrEmpty("WPIN_OUT");
  if (C.OutPath.empty()) {
    C.Rejected = "WPIN_OUT not set";
    return C;
  }

  const std::string Fns = envOrEmpty("WPIN_TARGET_FNS");
  const std::string ScopeVar = envOrEmpty("WPIN_SCOPE");
  std::vector<std::string> Names = splitCommas(Fns);

  if (!Names.empty()) {
    C.S = Scope::Functions;
    for (const std::string &N : Names) {
      if (std::find(C.Requested.begin(), C.Requested.end(), N) != C.Requested.end()) {
        C.Notes.push_back("WipePin: WPIN_TARGET_FNS names '" + N +
                          "' more than once; it is pinned once");
        continue;
      }
      C.Requested.push_back(N);
    }
    if (!ScopeVar.empty())
      C.Notes.push_back("WipePin: both WPIN_TARGET_FNS and WPIN_SCOPE are set; "
                        "WPIN_TARGET_FNS wins and the record says scope=functions");
  } else if (ScopeVar == "module") {
    C.S = Scope::Module;
  } else {
    C.Rejected = "no target";
    if (!Fns.empty())
      C.Notes.push_back("WipePin: WPIN_TARGET_FNS='" + Fns +
                        "' contains no function name");
    if (!ScopeVar.empty())
      C.Notes.push_back("WipePin: WPIN_SCOPE='" + ScopeVar +
                        "' is not 'module', the only scope value there is");
    if (Fns.empty() && ScopeVar.empty())
      C.Notes.push_back("WipePin: set WPIN_TARGET_FNS=<fn>[,<fn>...] or "
                        "WPIN_SCOPE=module");
    return C;
  }

  // The dry run is the red control. A value that is neither on nor off is
  // refused rather than read as off: reading WPIN_DRY_RUN=true as "not a dry
  // run" would mutate the object in the one cell whose job is to leave it alone.
  const std::string Dry = envOrEmpty("WPIN_DRY_RUN");
  if (Dry.empty() || Dry == "0") {
    C.DryRun = false;
  } else if (Dry == "1") {
    C.DryRun = true;
  } else {
    C.Rejected = "WPIN_DRY_RUN='" + Dry + "' is neither 0 nor 1";
    return C;
  }

  C.Valid = true;
  return C;
}

bool clearStaleRecord(std::string &Why) {
  const std::string Path = envOrEmpty("WPIN_OUT");
  if (Path.empty()) return true;

  // lstat, not stat: a symlink at WPIN_OUT is removed as a link, and what it
  // points to is left alone.
  llvm::sys::fs::file_status St;
  if (const std::error_code EC = llvm::sys::fs::status(Path, St, /*follow=*/false)) {
    if (EC == llvm::errc::no_such_file_or_directory) return true;
    Why = "cannot inspect WPIN_OUT (" + EC.message() + ")";
    return false;
  }
  const llvm::sys::fs::file_type T = St.type();
  if (T == llvm::sys::fs::file_type::directory_file) {
    Why = "WPIN_OUT is a directory";
    return false;
  }
  if (T != llvm::sys::fs::file_type::regular_file &&
      T != llvm::sys::fs::file_type::symlink_file) {
    // /dev/null, a fifo, a socket: not something to delete, and not somewhere a
    // record can be read back from either.
    Why = "WPIN_OUT is not a regular file";
    return false;
  }
  if (const std::error_code EC =
          llvm::sys::fs::remove(Path, /*IgnoreNonExisting=*/true)) {
    Why = "cannot remove the previous record at WPIN_OUT (" + EC.message() + ")";
    return false;
  }
  return true;
}

const char *resolutionName(Resolution R) {
  switch (R) {
  case Resolution::Resolved: return "resolved";
  case Resolution::DeclarationOnly: return "declaration-only";
  case Resolution::NotInModule: return "not-in-module";
  }
  return "not-in-module";
}

Resolution resolve(const llvm::Module &M, const std::string &Name) {
  const llvm::Function *F = M.getFunction(Name);
  if (!F) return Resolution::NotInModule;
  if (F->isDeclaration()) return Resolution::DeclarationOnly;
  return Resolution::Resolved;
}

} // namespace wpin
