#!/bin/bash
# second-language-measure — the whole measurement for the second language.
#
#   bash compiler/llvm-pass/scripts/second-language-measure.sh
#
# Reads:   nothing. The fixtures and the observer source are written out below,
#          so a run cannot pick up a stale or hand-edited copy, and no
#          measurement input sits under compiler/.
# Writes:  $SECOND_LANGUAGE_LAB (default $HOME/vg-lab/second-language)
# Decides: nothing. second-language-check.mjs grades the records.
#
# ── WHAT IS BEING MEASURED ──────────────────────────────────────────────────
#
# Whether a security property written in the second language survives its own
# compiler's optimiser. The property is the obvious one: a routine derives a
# secret into a buffer, uses it, and zeroes the buffer before returning.
#
# Three fixtures, all with the same control:
#
#   erasure-stack-local     the secret lives in a stack local and its consumers
#                           are ordinary in-crate functions.  EXPECT: lost.
#   erasure-opaque-consumer the same, except the consumers are opaque to the
#                           optimiser — the pointer is handed to two functions
#                           it has no body for.  EXPECT: lost as well. This
#                           fixture exists to test the belief that escaping to
#                           an opaque consumer protects the store. It does not:
#                           a stack slot is invisible to the caller once the
#                           frame is gone, whatever the callee did with the
#                           pointer, and the eliminating pass knows it.
#   erasure-retained-slot   the secret lives in memory that outlives the call,
#                           so the zeroing is observable.  EXPECT: survives.
#
# The control in all three is a function that zeroes memory its caller owns. It
# cannot be optimised away, and a run in which it disappears is a broken
# measurement rather than a finding.
#
# ── WHY A PLUGIN, AND WHY PINNED TO ONE BACKEND VERSION ─────────────────────
#
# The optimisation levels alone say the effect is gone; they do not say which
# pass took it. For that, an observer is loaded into the front end's real
# pipeline and counts call sites before and after every pass. The front end
# links against its own backend version, so the plugin is built against the
# version the front end reports, using a compiler driver from the newer
# toolchain: the older tree's CMake support files run a C-language probe that a
# CXX-only project does not satisfy, so the build is done directly rather than
# through CMake.
#
# ⚠ DO NOT rely on a version mismatch announcing itself. An earlier revision of
# this comment claimed that a plugin built against the wrong backend version is
# "rejected outright at load time rather than misbehaving — the good failure".
# That is not what was measured, and building on it would mean trusting a
# reading taken through a plugin that may never have run.
#
# What IS measured here:
#   · A structurally invalid shared object — no plugin entry point — is rejected
#     cleanly: exit 1, "failed to run LLVM passes: Failed to load pass plugin".
#     That message belongs to an unloadable object, not to a version mismatch.
#   · The same observer source built one major version too new produced NO such
#     message and exit 0. Adjacent releases share a plugin API version, so the
#     mismatch is not caught by the version check the way a distant one is —
#     the recorded rejection from an earlier probe involved a gap of several
#     major versions, which is a different situation entirely.
#   · What the too-new plugin does instead was NOT established. An adversarial
#     pass reports an abort inside the older backend's cast machinery; that has
#     not been reproduced here, and the positive control did not fire in the
#     harness used to look for it, so nothing about that run is interpretable.
#
# So the protection is the build below pinning the version, not a diagnostic
# downstream of it. If that pinning is ever changed, the way to tell whether the
# observer really ran is the HANDSHAKE line and a non-zero record count — never
# the exit code, which is 0 in both the working and the silent case.
set -u

LAB=${SECOND_LANGUAGE_LAB:-$HOME/vg-lab/second-language}
HERE=$(cd "$(dirname "$0")" && pwd)
TRACE_OPT=${SECOND_LANGUAGE_TRACE_OPT:-2}
OPT_LEVELS=${SECOND_LANGUAGE_OPT_LEVELS:-"0 1 2 3"}

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "second-language-measure: required tool $1 is not on PATH" >&2
  echo "second-language-measure: this is a failure, not a skip" >&2
  exit 3
}
need rustc
need node
need sha256sum

FRONTEND_BACKEND=$(rustc --version --verbose | sed -n 's/^LLVM version: //p')
[ -n "$FRONTEND_BACKEND" ] || { echo "second-language-measure: the front end did not report a backend version" >&2; exit 3; }
BACKEND_MAJOR=${FRONTEND_BACKEND%%.*}
BACKEND_CONFIG="llvm-config-$BACKEND_MAJOR"
need "$BACKEND_CONFIG"
need clang++-18

RUSTC_VERSION=$(rustc --version | awk '{print $2}')
CLANGXX_VERSION=$(clang++-18 --version | sed -n '1s/.*version \([0-9.]*\).*/\1/p')

rm -rf "$LAB"
mkdir -p "$LAB/fixtures" "$LAB/ir" "$LAB/trace" "$LAB/plugin" "$LAB/records"

# ── the observer ────────────────────────────────────────────────────────────
cat > "$LAB/plugin/SecondLanguageObserver.cpp" <<'CPP_EOF'
// Counts, before and after every pass in the host front end's own pipeline, the
// number of zeroing CALL SITES inside two named IR units: the subject and the
// control. It counts call sites and never the symbol, because a removed call
// leaves its declaration behind and a name search would blame whichever later
// pass sweeps declarations away.
//
// Output is one JSON object per line to $OBS_OUT, appended, flushed per line so
// that a crash mid-pipeline still leaves the history up to that point.
#include "llvm/ADT/Any.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace llvm;

namespace {

std::string envOr(const char *k, const char *d) {
  const char *v = getenv(k);
  return v ? std::string(v) : std::string(d);
}

unsigned countZeroingCallSites(const Function &F) {
  unsigned n = 0;
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB) {
      const auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;
      const Function *Callee = CB->getCalledFunction();
      if (!Callee)
        continue;
      if (Callee->getName().startswith("llvm.memset"))
        ++n;
    }
  return n;
}

struct Observer {
  std::string target, control, out;
  unsigned seq = 0;
  FILE *fh = nullptr;

  Observer() {
    target = envOr("OBS_TARGET_FN", "handle_request");
    control = envOr("OBS_CONTROL_FN", "wipe_kept");
    out = envOr("OBS_OUT", "");
    if (!out.empty())
      fh = fopen(out.c_str(), "a");
  }
  ~Observer() {
    if (fh)
      fclose(fh);
  }

  void emit(const char *phase, StringRef pass, StringRef unit, unsigned n) {
    if (!fh)
      return;
    fprintf(fh,
            "{\"seq\":%u,\"phase\":\"%s\",\"pass\":\"%.*s\",\"unit\":\"%.*s\","
            "\"callSites\":%u}\n",
            seq++, phase, (int)pass.size(), pass.data(), (int)unit.size(),
            unit.data(), n);
    fflush(fh);
  }

  void look(const char *phase, StringRef pass, Any IR) {
    if (const auto **MP = any_cast<const Module *>(&IR)) {
      for (const Function &F : **MP) {
        if (F.isDeclaration())
          continue;
        if (F.getName() == target || F.getName() == control)
          emit(phase, pass, F.getName(), countZeroingCallSites(F));
      }
      return;
    }
    if (const auto **FP = any_cast<const Function *>(&IR)) {
      const Function &F = **FP;
      if (F.isDeclaration())
        return;
      if (F.getName() == target || F.getName() == control)
        emit(phase, pass, F.getName(), countZeroingCallSites(F));
    }
  }
};

Observer &obs() {
  static Observer O;
  return O;
}

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "SecondLanguageObserver", "0.1",
          [](PassBuilder &PB) {
            PassInstrumentationCallbacks *PIC =
                PB.getPassInstrumentationCallbacks();
            if (!PIC)
              return;
            PIC->registerBeforeNonSkippedPassCallback(
                [](StringRef P, Any IR) { obs().look("before", P, IR); });
            PIC->registerAfterPassCallback(
                [](StringRef P, Any IR, const PreservedAnalyses &) {
                  obs().look("after", P, IR);
                });
          }};
}
CPP_EOF

PLUGIN="$LAB/plugin/libSecondLanguageObserver.so"
# The flag expansion below is deliberately unquoted: the backend's config tool
# prints a whole argument list on one line and it has to word-split.
if ! clang++-18 -shared -fPIC -Wno-deprecated-declarations \
      $($BACKEND_CONFIG --cxxflags) -o "$PLUGIN" \
      "$LAB/plugin/SecondLanguageObserver.cpp" 2> "$LAB/plugin/build.log"; then
  echo "second-language-measure: the observer did not build against backend $FRONTEND_BACKEND" >&2
  sed -n 1,20p "$LAB/plugin/build.log" >&2
  exit 1
fi

# ── the fixtures ────────────────────────────────────────────────────────────
# The subject is always handle_request and the control is always wipe_kept, so
# that one observer configuration covers all three.

cat > "$LAB/fixtures/erasure-stack-local.rs" <<'RS_EOF'
use core::ptr::write_bytes;
const N: usize = 64;

#[inline(never)]
fn derive_key(seed: u64, out: &mut [u8; N]) {
    let mut x = seed | 1;
    let mut i = 0;
    while i < N {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out[i] = (x >> 56) as u8;
        i += 1;
    }
}

#[inline(never)]
fn fold(buf: &[u8; N]) -> u64 {
    let mut a: u64 = 0;
    let mut i = 0;
    while i < N {
        a = a.wrapping_mul(31).wrapping_add(buf[i] as u64);
        i += 1;
    }
    a
}

/// SUBJECT. The secret is a stack local. Zeroing it before returning is the
/// security property; nothing reads it afterwards, so the optimiser is free to
/// decide the write has no effect.
#[no_mangle]
pub extern "C" fn handle_request(seed: u64) -> u64 {
    let mut slot = core::mem::MaybeUninit::<[u8; N]>::uninit();
    let secret: &mut [u8; N] = unsafe { &mut *slot.as_mut_ptr() };
    derive_key(seed, secret);
    let tag = fold(secret);
    unsafe { write_bytes(secret.as_mut_ptr(), 0u8, N) };
    tag
}

/// CONTROL. Zeroes memory the caller owns, so the write is observable and no
/// optimisation level may remove it.
#[no_mangle]
pub extern "C" fn wipe_kept(out: *mut u8) {
    unsafe { write_bytes(out, 0u8, N) };
}
RS_EOF

cat > "$LAB/fixtures/erasure-opaque-consumer.rs" <<'RS_EOF'
use core::ptr::write_bytes;
const N: usize = 64;

// No bodies. The optimiser has to assume these do anything at all with the
// pointer, including keeping a copy of it.
extern "C" {
    fn opaque_derive(seed: u64, out: *mut u8);
    fn opaque_fold(p: *const u8) -> u64;
}

/// SUBJECT. Same shape as erasure-stack-local, except that the secret's address
/// leaves the function twice, into code the optimiser cannot see. The belief
/// under test is that this protects the zeroing.
#[no_mangle]
pub extern "C" fn handle_request(seed: u64) -> u64 {
    let mut slot = core::mem::MaybeUninit::<[u8; N]>::uninit();
    let secret: *mut u8 = slot.as_mut_ptr() as *mut u8;
    unsafe { opaque_derive(seed, secret) };
    let tag = unsafe { opaque_fold(secret) };
    unsafe { write_bytes(secret, 0u8, N) };
    tag
}

/// CONTROL.
#[no_mangle]
pub extern "C" fn wipe_kept(out: *mut u8) {
    unsafe { write_bytes(out, 0u8, N) };
}
RS_EOF

cat > "$LAB/fixtures/erasure-retained-slot.rs" <<'RS_EOF'
use core::ptr::write_bytes;
const N: usize = 64;

// The secret lives in memory that outlives the call, so zeroing it is a write
// somebody else can read, and no optimisation level may drop it.
static mut SLOT: [u8; N] = [0; N];

#[inline(never)]
fn derive_key(seed: u64, out: &mut [u8; N]) {
    let mut x = seed | 1;
    let mut i = 0;
    while i < N {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out[i] = (x >> 56) as u8;
        i += 1;
    }
}

#[inline(never)]
fn fold(buf: &[u8; N]) -> u64 {
    let mut a: u64 = 0;
    let mut i = 0;
    while i < N {
        a = a.wrapping_mul(31).wrapping_add(buf[i] as u64);
        i += 1;
    }
    a
}

/// SUBJECT.
#[no_mangle]
pub extern "C" fn handle_request(seed: u64) -> u64 {
    unsafe {
        derive_key(seed, &mut SLOT);
        let tag = fold(&SLOT);
        write_bytes(SLOT.as_mut_ptr(), 0u8, N);
        tag
    }
}

/// CONTROL.
#[no_mangle]
pub extern "C" fn wipe_kept(out: *mut u8) {
    unsafe { write_bytes(out, 0u8, N) };
}
RS_EOF

FIXTURES="erasure-stack-local erasure-opaque-consumer erasure-retained-slot"

inputs=0
checked=0
skipped=0
fail=0

for FX in $FIXTURES; do
  inputs=$((inputs + 1))
  ok=1
  for O in $OPT_LEVELS; do
    if ! rustc --crate-type=rlib --edition=2021 -C opt-level="$O" \
          --emit=llvm-ir="$LAB/ir/$FX-O$O.ll" -o "$LAB/ir/$FX-O$O.rlib" \
          "$LAB/fixtures/$FX.rs" 2> "$LAB/ir/$FX-O$O.log"; then
      echo "second-language-measure: $FX -O$O did not compile" >&2
      sed -n 1,10p "$LAB/ir/$FX-O$O.log" >&2
      ok=0
      break
    fi
  done
  if [ "$ok" -eq 1 ]; then
    OBS_OUT="$LAB/trace/$FX-O$TRACE_OPT.jsonl" \
    OBS_TARGET_FN=handle_request OBS_CONTROL_FN=wipe_kept \
    RUSTC_BOOTSTRAP=1 rustc --crate-type=rlib --edition=2021 -C opt-level="$TRACE_OPT" \
      -Z llvm-plugins="$PLUGIN" --emit=obj -o "$LAB/ir/$FX-traced.o" \
      "$LAB/fixtures/$FX.rs" 2> "$LAB/trace/$FX.log"
    if [ ! -s "$LAB/trace/$FX-O$TRACE_OPT.jsonl" ]; then
      echo "second-language-measure: $FX produced no pass trace; the observer did not run" >&2
      sed -n 1,10p "$LAB/trace/$FX.log" >&2
      ok=0
    fi
  fi
  if [ "$ok" -eq 1 ]; then checked=$((checked + 1)); else fail=1; fi
done

# Did loading the observer change the output? If it did, the observation is not
# of the compilation that would otherwise have happened.
IDENTICAL=unknown
FX=erasure-stack-local
SOURCE_DATE_EPOCH=1700000000 rustc --crate-type=rlib --edition=2021 -C opt-level="$TRACE_OPT" \
  -C metadata=pinned --emit=obj -o "$LAB/ir/identity-plain.o" "$LAB/fixtures/$FX.rs" 2>/dev/null
OBS_OUT=/dev/null OBS_TARGET_FN=handle_request OBS_CONTROL_FN=wipe_kept \
SOURCE_DATE_EPOCH=1700000000 RUSTC_BOOTSTRAP=1 rustc --crate-type=rlib --edition=2021 \
  -C opt-level="$TRACE_OPT" -C metadata=pinned --emit=obj -Z llvm-plugins="$PLUGIN" \
  -o "$LAB/ir/identity-observed.o" "$LAB/fixtures/$FX.rs" 2>/dev/null
if [ -s "$LAB/ir/identity-plain.o" ] && [ -s "$LAB/ir/identity-observed.o" ]; then
  a=$(sha256sum < "$LAB/ir/identity-plain.o" | cut -d' ' -f1)
  b=$(sha256sum < "$LAB/ir/identity-observed.o" | cut -d' ' -f1)
  [ "$a" = "$b" ] && IDENTICAL=yes || IDENTICAL=no
fi

TOOL_DIGEST=$(printf '%s\n' "rustc $RUSTC_VERSION" "backend $FRONTEND_BACKEND" \
  "clang++ $CLANGXX_VERSION" | sha256sum | cut -d' ' -f1)

OPT_JSON=$(printf '%s\n' $OPT_LEVELS | paste -sd, -)

cat > "$LAB/meta.json" <<META_EOF
{
  "language": {
    "backend": "llvm",
    "backendVersion": "$FRONTEND_BACKEND",
    "name": "rust",
    "version": "$RUSTC_VERSION"
  },
  "optLevels": [$OPT_JSON],
  "traceOptLevel": $TRACE_OPT,
  "toolchain": {
    "clang": "$CLANGXX_VERSION",
    "digest": "$TOOL_DIGEST",
    "observedOutputIdenticalToUnobserved": "$IDENTICAL",
    "packages": ["rustc $RUSTC_VERSION", "backend $FRONTEND_BACKEND", "clang++ $CLANGXX_VERSION"],
    "rustc": "$RUSTC_VERSION"
  },
  "fixtures": [
    { "name": "erasure-stack-local", "propertyId": "erasure.wipe",
      "subject": "handle_request", "control": "wipe_kept",
      "sourceRel": "fixtures/erasure-stack-local.rs",
      "expectation": "LOST_AT_HIGH_OPT" },
    { "name": "erasure-opaque-consumer", "propertyId": "erasure.wipe",
      "subject": "handle_request", "control": "wipe_kept",
      "sourceRel": "fixtures/erasure-opaque-consumer.rs",
      "expectation": "LOST_AT_HIGH_OPT" },
    { "name": "erasure-retained-slot", "propertyId": "erasure.wipe",
      "subject": "handle_request", "control": "wipe_kept",
      "sourceRel": "fixtures/erasure-retained-slot.rs",
      "expectation": "SURVIVES" }
  ]
}
META_EOF

echo "second-language-measure: inputs=$inputs checked=$checked skipped=$skipped"
echo "second-language-measure: object identical with and without the observer: $IDENTICAL"
if [ "$inputs" -eq 0 ]; then
  echo "second-language-measure: nothing was measured; an empty run is not a clean run" >&2
  exit 3
fi
if [ "$fail" -ne 0 ]; then exit 1; fi

node "$HERE/second-language-record.mjs" --lab "$LAB" || exit $?
node "$HERE/second-language-check.mjs" --records "$LAB/records"
exit $?
