// Canonical JSON + SHA-256, per interfaces.md §5.
//
// The rules are not ours to choose: an independent verifier already implements
// them, and a record that disagrees with it is a malformed record even if it
// parses. What is implemented here:
//
//   1. `context` and `evidenceDigest` are removed as whole subtrees from the
//      TOP LEVEL only, before digesting. Nothing else is removed at any depth.
//   2. Object keys sort lexicographically at every level, including inside
//      arrays of objects. Array order itself is never sorted.
//   3. No insignificant whitespace.
//   4. Every number is an integer. A non-integral number makes canonicalisation
//      FAIL rather than round — see `canonicalize`'s error return.
//   5. SHA-256 over the UTF-8 bytes, lowercase hex.
#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"

#include <string>

namespace intentgate {

/// Serialise `V` in canonical form into `Out`.
///
/// Returns false and fills `Err` when the value cannot be canonicalised. The
/// only such case today is rule 4: a `Number` that is not an integer. We fail
/// instead of rounding because a rounded ratio is a silently wrong record, and
/// this directory exists to catch exactly that class of silent difference.
bool canonicalize(const llvm::json::Value &V, std::string &Out, std::string &Err);

/// Canonicalise `Top` with `context` and `evidenceDigest` removed from the top
/// level, then SHA-256 it. `Top` is not modified.
bool evidenceDigest(const llvm::json::Object &Top, std::string &OutHex, std::string &Err);

/// Lowercase hex SHA-256 of the given bytes.
std::string sha256Hex(llvm::StringRef Bytes);

/// Lowercase hex SHA-256 of a file's contents. Returns false if it cannot be
/// read — never a zero digest, because "unreadable" and "empty" are different
/// claims and merging them is how a pin starts lying.
bool sha256File(llvm::StringRef Path, std::string &OutHex);

} // namespace intentgate
