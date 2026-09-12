// What WipePinGcc was asked to do. The GCC twin of
// compiler/llvm-repair/src/PinSelector.h: the same four variables, the same
// refusals, the same wording, with the prefix `WipePinGcc:` on every line.
//
//   WPIN_OUT          record path (required)
//   WPIN_TARGET_FNS   comma separated function names    } one of the two is
//   WPIN_SCOPE        "module": every defined function  } required; the first
//                                                          wins if both are set
//   WPIN_DRY_RUN      "1": write the record as if pinning, change nothing
//
// Every way of getting this wrong is loud, for the reason PinSelector.h gives:
// a plugin that quietly declines to install leaves a build that succeeded and
// looks, in every other respect, like one that was repaired.
//
// Nothing here includes a GCC header. Name resolution, which needs the
// compilation, lives in WipePinGcc.cpp.

#ifndef WPG_CONFIG_H
#define WPG_CONFIG_H

#include <string>
#include <vector>

namespace wpg {

enum class Scope { Functions, Module };

struct Config {
  std::string OutPath;
  Scope S = Scope::Functions;
  /// The names asked for, in the order given, duplicates dropped.
  std::vector<std::string> Requested;
  bool DryRun = false;

  bool Valid = false;
  /// The tail of the refusal line when !Valid. The line printed is exactly
  /// "WipePinGcc: refusing to install: " + Rejected.
  std::string Rejected;
  /// Extra lines explaining a refusal, or noting something non-fatal. Printed
  /// after the refusal line, if any.
  std::vector<std::string> Notes;
};

/// Reads the WPIN_* environment. Never throws, never exits.
Config loadConfig();

/// If WPIN_OUT is set and non-empty, removes whatever is there. Called first
/// in plugin_init -- before the version check, before loadConfig(), before any
/// refusal -- so that after a compile "there is a record" can only mean "this
/// compile wrote it". Returns false, with the reason in `Why`, when something
/// is at WPIN_OUT and could not be removed: a directory, a non-regular file,
/// or an unlink that failed for a reason other than "it is not there". Nothing
/// at WPIN_OUT is not a failure. Same semantics as wpin::clearStaleRecord,
/// with lstat(2) where that one uses llvm::sys::fs::status(follow=false).
bool clearStaleRecord(std::string &Why);

/// Writes `Text` to `Path`, replacing what is there. On failure returns false
/// with strerror's text in `Why`. Lives here, outside the translation unit
/// that includes GCC's system.h, which poisons strerror and rewrites the stdio
/// calls to their _unlocked forms.
bool writeTextFile(const std::string &Path, const std::string &Text, std::string &Why);

} // namespace wpg

#endif
