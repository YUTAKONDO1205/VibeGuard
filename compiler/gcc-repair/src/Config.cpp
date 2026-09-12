#include "Config.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/stat.h>
#include <unistd.h>

namespace wpg {

namespace {

/// Unset and empty are the same thing, as in PinSelector.cpp: an exported but
/// empty variable is what a shell leaves after `WPIN_OUT=$maybe_unset`.
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
        C.Notes.push_back("WipePinGcc: WPIN_TARGET_FNS names '" + N +
                          "' more than once; it is pinned once");
        continue;
      }
      C.Requested.push_back(N);
    }
    if (!ScopeVar.empty())
      C.Notes.push_back("WipePinGcc: both WPIN_TARGET_FNS and WPIN_SCOPE are set; "
                        "WPIN_TARGET_FNS wins and the record says scope=functions");
  } else if (ScopeVar == "module") {
    C.S = Scope::Module;
  } else {
    C.Rejected = "no target";
    if (!Fns.empty())
      C.Notes.push_back("WipePinGcc: WPIN_TARGET_FNS='" + Fns +
                        "' contains no function name");
    if (!ScopeVar.empty())
      C.Notes.push_back("WipePinGcc: WPIN_SCOPE='" + ScopeVar +
                        "' is not 'module', the only scope value there is");
    if (Fns.empty() && ScopeVar.empty())
      C.Notes.push_back("WipePinGcc: set WPIN_TARGET_FNS=<fn>[,<fn>...] or "
                        "WPIN_SCOPE=module");
    return C;
  }

  // The dry run is the red control. A value that is neither on nor off is
  // refused rather than read as off: reading WPIN_DRY_RUN=true as "not a dry
  // run" would change the object in the one cell whose job is to leave it
  // alone.
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
  struct stat St;
  if (lstat(Path.c_str(), &St) != 0) {
    if (errno == ENOENT) return true;
    Why = std::string("cannot inspect WPIN_OUT (") + std::strerror(errno) + ")";
    return false;
  }
  if (S_ISDIR(St.st_mode)) {
    Why = "WPIN_OUT is a directory";
    return false;
  }
  if (!S_ISREG(St.st_mode) && !S_ISLNK(St.st_mode)) {
    // /dev/null, a fifo, a socket: not something to delete, and not somewhere
    // a record can be read back from either.
    Why = "WPIN_OUT is not a regular file";
    return false;
  }
  if (unlink(Path.c_str()) != 0 && errno != ENOENT) {
    Why = std::string("cannot remove the previous record at WPIN_OUT (") +
          std::strerror(errno) + ")";
    return false;
  }
  return true;
}

bool writeTextFile(const std::string &Path, const std::string &Text, std::string &Why) {
  std::FILE *Out = std::fopen(Path.c_str(), "w");
  if (!Out) {
    Why = std::strerror(errno);
    return false;
  }
  const bool Wrote = std::fwrite(Text.data(), 1, Text.size(), Out) == Text.size();
  const int WriteErr = errno;
  const bool Closed = std::fclose(Out) == 0;
  if (!Wrote || !Closed) {
    Why = std::strerror(Wrote ? errno : WriteErr);
    return false;
  }
  return true;
}

} // namespace wpg
