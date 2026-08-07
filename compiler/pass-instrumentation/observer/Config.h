//===- Config.h - how the observer is told what to watch ------------------===//
//
// Part of the property observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// Everything the observer needs arrives through the environment, because the
// plugin is loaded by a compiler driver whose command line belongs to the build
// system rather than to us. Adding a flag would mean changing that command
// line, and a changed command line is a changed compilation -- the one thing
// this component exists to avoid.
//
//===----------------------------------------------------------------------===//

#ifndef PROPERTY_OBSERVER_CONFIG_H
#define PROPERTY_OBSERVER_CONFIG_H

#include <string>
#include <vector>

namespace propobs {

/// How much the observer records.
///
/// The distinction is only in what is written out. All three modes run the same
/// state machine over the same observations, so a Standard run and a Trace run
/// of the same compilation agree on the attribution; Trace simply also shows
/// the passes where nothing changed.
enum class Mode {
  /// Boundaries only: state changes, unit births and deaths, the summary.
  Standard,
  /// Every pass, every observation of a tracked unit, whether or not anything
  /// changed. This is what the ground-truth harness reads.
  Trace,
  /// Trace, plus the IR of the tracked unit written out at every boundary where
  /// its count changed, so that a driver can re-apply its own predicate to
  /// exactly the IR this plugin counted instead of trusting the count.
  Forensic,
};

struct Config {
  std::string TargetFn;
  std::string ControlFn;
  std::vector<std::string> EffectSymbols;
  std::string OutPath;
  std::string SnapshotDir;

  /// For properties whose protection is a branch: the reporting call only
  /// counts while the branch that guards it still depends on a value. Without
  /// this the plugin counts an already-neutralised check as present, and then
  /// disagrees with the other observation channels -- which is the failure this
  /// flag exists to prevent, since all of them must be asking the same question
  /// for their agreement to mean anything.
  bool RequireLiveBranch = false;

  Mode ObsMode = Mode::Standard;

  bool Valid = false;
  /// Why the configuration was rejected. Empty when Valid.
  std::string Rejected;
};

/// Read the configuration from OBS_* environment variables.
Config loadConfig();

const char *modeName(Mode M);

std::vector<std::string> splitCommas(const std::string &S);

} // namespace propobs

#endif // PROPERTY_OBSERVER_CONFIG_H
