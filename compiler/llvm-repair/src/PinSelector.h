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
//
// The same goes for a record left behind by an earlier compile. Before anything
// else is decided -- before any refusal -- whatever is at WPIN_OUT is removed
// (clearStaleRecord), so that after this compile "there is a record" can only
// mean "this compile wrote it".

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

/// If WPIN_OUT is set and non-empty, removes whatever record is there. Called
/// when the plugin is loaded, before loadConfig(), so that it happens even in a
/// compile that is then refused, and even in one whose pass never runs
/// (`-Xclang -disable-llvm-passes`): in every such compile the answer to "is
/// there a record?" is then "no", which is what the compile produced.
///
/// Returns false, with the reason in `Why`, when something is at WPIN_OUT and
/// could not be removed -- a directory, a non-regular file, or an unlink that
/// failed for any reason other than "it is not there". Nothing at WPIN_OUT is
/// not a failure. The caller refuses to install on false: an old record that
/// cannot be cleared would still be there after any compile whose pass then
/// failed to write, looking like that compile's.
bool clearStaleRecord(std::string &Why);

enum class Resolution { Resolved, DeclarationOnly, NotInModule };

/// The three words the observer under compiler/pass-instrumentation/observer/
/// uses for the same question (its SUBJECTRES record), so a reader sees one
/// vocabulary for "did the name you gave me exist".
const char *resolutionName(Resolution R);

Resolution resolve(const llvm::Module &M, const std::string &Name);

} // namespace wpin

#endif
