//===- Config.cpp ---------------------------------------------------------===//
//
// Part of the introduction observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//

#include "Config.h"

#include <cstdlib>

namespace introobs {

const char *modeName(Mode M) {
  switch (M) {
  case Mode::Standard: return "standard";
  case Mode::Trace: return "trace";
  }
  return "unknown";
}

std::vector<std::string> splitCommas(const std::string &S) {
  std::vector<std::string> Out;
  std::string Cur;
  for (char C : S) {
    if (C == ',') {
      if (!Cur.empty()) Out.push_back(Cur);
      Cur.clear();
    } else if (C != ' ' && C != '\t') {
      Cur.push_back(C);
    }
  }
  if (!Cur.empty()) Out.push_back(Cur);
  return Out;
}

static std::string env(const char *Name) {
  const char *V = std::getenv(Name);
  return V ? std::string(V) : std::string();
}

Config loadConfig() {
  Config C;
  C.OutPath = env("INTRO_OUT");
  C.ControlFn = env("INTRO_CONTROL_FN");

  const std::string M = env("INTRO_MODE");
  if (M == "trace") C.ObsMode = Mode::Trace;
  else if (!M.empty() && M != "standard") {
    C.Rejected = "INTRO_MODE must be 'standard' or 'trace', not '" + M + "'";
    return C;
  }

  const std::string W = env("INTRO_WATCH");
  if (!W.empty()) {
    C.Watched = Watch{false, false, false, false};
    for (const std::string &K : splitCommas(W)) {
      if (K == "symbols") C.Watched.Symbols = true;
      else if (K == "extcalls") C.Watched.ExternalCalls = true;
      else if (K == "initialisers") C.Watched.Initialisers = true;
      else if (K == "sections") C.Watched.Sections = true;
      else {
        C.Rejected = "INTRO_WATCH: unknown element kind '" + K + "'";
        return C;
      }
    }
    if (!C.Watched.Symbols && !C.Watched.ExternalCalls &&
        !C.Watched.Initialisers && !C.Watched.Sections) {
      C.Rejected = "INTRO_WATCH selected no element kinds; there would be "
                   "nothing to observe and an empty log reads as 'nothing "
                   "appeared'";
      return C;
    }
  }

  if (C.OutPath.empty()) {
    C.Rejected = "INTRO_OUT is not set; refusing to observe into nowhere";
    return C;
  }

  // A control is required rather than optional. Without one there is no way,
  // afterwards, to tell a run in which nothing was introduced from a run in
  // which the observer was never installed -- and those produce the same empty
  // log. interfaces.md §4.
  if (C.ControlFn.empty()) {
    C.Rejected = "INTRO_CONTROL_FN is not set; a measurement with no control "
                 "cannot be told apart from a measurement that did not happen";
    return C;
  }

  C.Valid = true;
  return C;
}

} // namespace introobs
