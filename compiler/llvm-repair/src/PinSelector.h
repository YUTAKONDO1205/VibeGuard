// What WipePin was asked to do, and whether the names it was given exist.
//
// Configuration is by environment variable, like the observers next door, so
// that loading the plugin is the only change to a compile command:
//
//   WPIN_OUT          record path (required)
//   WPIN_TARGET_FNS   comma separated function names    } one of the two is
//   WPIN_SCOPE        "module": every defined function  } required; the first
//                                                          wins if both are set
//   WPIN_DRY_RUN      "1": write the record as if pinning, change nothing
//
// Every way of getting this wrong is loud. A plugin that quietly declines to
// install leaves a build that succeeded and looks, in every other respect, like
// one that was repaired -- which is the reading this component must never make
// possible.

#ifndef WPIN_PINSELECTOR_H
#define WPIN_PINSELECTOR_H

#include <string>
#include <vector>

namespace llvm {
class Module;
}

namespace wpin {

enum class Scope { Functions, Module };

struct Config {
  std::string OutPath;
  Scope S = Scope::Functions;
  /// The names asked for, in the order given, duplicates dropped.
  std::vector<std::string> Requested;
  bool DryRun = false;

  bool Valid = false;
  /// The tail of the refusal line when !Valid. The line printed is exactly
  /// "WipePin: refusing to install: " + Rejected, so a caller can match it.
  std::string Rejected;
  /// Extra lines explaining a refusal, or noting something non-fatal (both
  /// selectors set, a duplicate name). Printed after the refusal line, if any.
  std::vector<std::string> Notes;
};

/// Reads the WPIN_* environment. Never throws, never exits.
Config loadConfig();

enum class Resolution { Resolved, DeclarationOnly, NotInModule };

/// The three words the observer under compiler/pass-instrumentation/observer/
/// uses for the same question (its SUBJECTRES record), so a reader sees one
/// vocabulary for "did the name you gave me exist".
const char *resolutionName(Resolution R);

Resolution resolve(const llvm::Module &M, const std::string &Name);

} // namespace wpin

#endif
