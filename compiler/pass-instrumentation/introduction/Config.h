//===- Config.h - how the introduction observer is told what to watch -----===//
//
// Part of the introduction observer plugin. Licence: Apache-2.0 WITH
// LLVM-exception (see compiler/LICENSE).
//
//===----------------------------------------------------------------------===//
//
// Configuration arrives through the environment for the same reason it does in
// the property observer: the plugin is loaded by a driver whose command line
// belongs to the build system. Adding a flag would mean changing that command
// line, and a changed command line is a changed compilation -- which is the one
// thing an observer must not be.
//
//===----------------------------------------------------------------------===//

#ifndef INTRODUCTION_OBSERVER_CONFIG_H
#define INTRODUCTION_OBSERVER_CONFIG_H

#include <string>
#include <vector>

namespace introobs {

enum class Mode {
  /// Transitions only: the introduction, every later loss and reintroduction,
  /// and the summary. The state series is whole in either mode -- what Trace
  /// adds is the observations where nothing changed.
  Standard,
  /// Every pass, and every observation of every tracked element.
  Trace,
};

/// Which kinds of element are watched. All four by default; narrowing is for
/// measurement runs that want a small log, never for a check.
struct Watch {
  bool Symbols = true;
  bool ExternalCalls = true;
  bool Initialisers = true;
  bool Sections = true;
};

struct Config {
  std::string OutPath;
  /// A function that must stay live and keep its effect for the whole
  /// pipeline. interfaces.md §4: a measurement whose control also went to zero
  /// is a broken measurement rather than a finding, and there is no way to tell
  /// the two apart afterwards without one.
  std::string ControlFn;
  Watch Watched;
  Mode ObsMode = Mode::Standard;

  bool Valid = false;
  /// Why the configuration was rejected. Empty when Valid.
  std::string Rejected;
};

Config loadConfig();
const char *modeName(Mode M);
std::vector<std::string> splitCommas(const std::string &S);

} // namespace introobs

#endif // INTRODUCTION_OBSERVER_CONFIG_H
