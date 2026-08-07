//===- Config.cpp ---------------------------------------------------------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//

#include "Config.h"

#include <cstdlib>

namespace propobs {

static std::string envOr(const char *Name, const char *Default) {
  const char *V = std::getenv(Name);
  return V ? std::string(V) : std::string(Default);
}

std::vector<std::string> splitCommas(const std::string &S) {
  std::vector<std::string> Out;
  std::string Cur;
  for (char C : S) {
    if (C == ',') {
      if (!Cur.empty())
        Out.push_back(Cur);
      Cur.clear();
    } else {
      Cur.push_back(C);
    }
  }
  if (!Cur.empty())
    Out.push_back(Cur);
  return Out;
}

const char *modeName(Mode M) {
  switch (M) {
  case Mode::Standard:
    return "standard";
  case Mode::Trace:
    return "trace";
  case Mode::Forensic:
    return "forensic";
  }
  return "standard";
}

static Mode parseMode(const std::string &S, bool &Known) {
  Known = true;
  if (S == "standard" || S.empty())
    return Mode::Standard;
  if (S == "trace")
    return Mode::Trace;
  if (S == "forensic")
    return Mode::Forensic;
  Known = false;
  return Mode::Standard;
}

Config loadConfig() {
  Config C;
  C.TargetFn = envOr("OBS_TARGET_FN", "");
  C.ControlFn = envOr("OBS_CONTROL_FN", "");
  C.EffectSymbols = splitCommas(envOr("OBS_EFFECT_SYMBOLS", ""));
  C.OutPath = envOr("OBS_OUT", "");
  C.SnapshotDir = envOr("OBS_SNAPSHOT_DIR", "");
  C.RequireLiveBranch = envOr("OBS_REQUIRE_LIVE_BRANCH", "0") == "1";

  bool ModeKnown = false;
  C.ObsMode = parseMode(envOr("OBS_MODE", "standard"), ModeKnown);

  // Fail closed on configuration, and say which field is missing. A plugin that
  // silently observes nothing produces an empty log, and an empty log that a
  // driver reads as "nothing was lost" is the failure mode this component is
  // supposed to make impossible.
  if (C.TargetFn.empty())
    C.Rejected = "OBS_TARGET_FN is not set";
  else if (C.ControlFn.empty())
    C.Rejected = "OBS_CONTROL_FN is not set";
  else if (C.EffectSymbols.empty())
    C.Rejected = "OBS_EFFECT_SYMBOLS is not set";
  else if (C.OutPath.empty())
    C.Rejected = "OBS_OUT is not set";
  else if (!ModeKnown)
    C.Rejected = "OBS_MODE is not one of standard, trace, forensic";
  else if (C.ObsMode == Mode::Forensic && C.SnapshotDir.empty())
    C.Rejected = "OBS_MODE=forensic requires OBS_SNAPSHOT_DIR";

  C.Valid = C.Rejected.empty();
  return C;
}

} // namespace propobs
