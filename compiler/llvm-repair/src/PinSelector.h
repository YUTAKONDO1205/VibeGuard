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
//   WPIN_BARRIER_CALLS "1": also repair a zero-fill memset that reaches
//                     pipeline start as a call rather than the intrinsic --
//                     the -D_FORTIFY_SOURCE wrapper (memset.inline),
//                     __memset_chk, or a libcall memset -- by putting an
//                     opaque read of its destination right after it (see
//                     WipePin.cpp), and bzero / bzero.<suffix> likewise.
//                     Unset or "0": off; such calls are only counted.
//   WPIN_ZERO_COPY    "1": also repair a wipe written as a
//                     copy from an all-zero constant global -- memcpy(p,
//                     zeros, n) with `static const unsigned char zeros[N];`.
//                     The llvm.memcpy is replaced by a volatile llvm.memset
//                     of the same destination and length; a call to memcpy,
//                     __memcpy_chk or memcpy.<suffix> (the -D_FORTIFY_SOURCE
//                     wrapper) gets the same barrier as WPIN_BARRIER_CALLS.
//                     Unset or "0": off; such copies are only counted.
//   WPIN_BUFFER_BARRIER "1": for every stack buffer of a function in scope
//                     that is the destination of a zero fill -- a zero-fill
//                     memset or memset-shaped call, a store of a zero constant
//                     inside a loop (an aggregate buffer only), or a copy from
//                     an all-zero constant global -- put an opaque read of the
//                     buffer directly before each of its llvm.lifetime.end
//                     calls, or before every `ret` when it has none (see
//                     WipePin.cpp, "the buffer barrier";
//                     ../schema/wipe-pin.md section 14.6). Unset or "0": off.
//
// The three switches are read after WPIN_DRY_RUN, in that order, and anything
// but unset, empty, "0" or "1" is refused (wipe-pin-v3). With all three off the
// plugin changes the code exactly as the v2 plugin did; the record says which
// were on as barrierCalls.enabled, zeroCopy.enabled, bufferBarriers.enabled.
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
  /// WPIN_BARRIER_CALLS=1.
  bool BarrierCalls = false;
  /// WPIN_ZERO_COPY=1.
  bool ZeroCopy = false;
  /// WPIN_BUFFER_BARRIER=1.
  bool BufferBarrier = false;

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
///
/// `Removed` is set to true when a file (or a symlink) was actually removed, and
/// left alone otherwise. It is what lets the link-time line say whether loading
/// the plugin just deleted a record (see WipePin.cpp).
bool clearStaleRecord(std::string &Why, bool &Removed);

enum class Resolution { Resolved, DeclarationOnly, NotInModule };

/// The three words the observer under compiler/pass-instrumentation/observer/
/// uses for the same question (its SUBJECTRES record), so a reader sees one
/// vocabulary for "did the name you gave me exist".
const char *resolutionName(Resolution R);

Resolution resolve(const llvm::Module &M, const std::string &Name);

} // namespace wpin

#endif
