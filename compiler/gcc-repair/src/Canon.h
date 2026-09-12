// Canonical JSON records, to the rules in compiler/schema/interfaces.md
// section 5, without LLVM.
//
// The LLVM side writes its records with compiler/llvm-pass/src/Record.cpp,
// which gets SHA-256 from llvm::SHA256. A GCC plugin cannot link libLLVM, so
// this is a second writer of the same text. Two writers of one canonical form
// agree only if something checks that they do, and the check is the shared
// calibration in compiler/evidence/testdata/digest-vectors.json: every vector
// there is run through this file by test/canon-vectors.cpp (see README.md,
// "Building"), and a writer that disagrees with a vector has a bug in its
// serialisation, not a finding about any record.
//
// Same deliberate omission as Record.h: there is no floating-point
// constructor. Rule 4 says every number in a record is an integer; the cheapest
// way to obey it is to make the alternative unspellable.
//
// Nothing here includes a GCC header, so the test binary builds and runs
// without the plugin headers and without a GCC to load into.

#ifndef WPG_CANON_H
#define WPG_CANON_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wpg {

/// Object keys in the order canon.mjs puts them: `Object.keys(v).sort()`, which
/// compares UTF-16 code units. For ASCII keys that is byte order; it differs
/// from UTF-8 byte order only between a key holding a character in U+E000 to
/// U+FFFF and one holding a character above U+FFFF (the surrogate pair sorts
/// first in UTF-16, the four-byte sequence last in UTF-8). No vector in the
/// shared calibration separates the two orders; test/canon-vectors.cpp adds
/// one, with its expected text taken from canon.mjs.
///
/// Bytes that are not well-formed UTF-8 compare as themselves, one unit per
/// byte. A record written by this plugin carries none: every key is a literal
/// in WipePinGcc.cpp.
struct Utf16KeyLess {
  bool operator()(const std::string &A, const std::string &B) const;
};

class Json {
public:
  enum class Kind { Null, Bool, Int, Str, Arr, Obj };

  Json() : K(Kind::Null) {}

  static Json null();
  static Json boolean(bool B);
  /// Any int64. canon.mjs refuses integers outside +-(2^53 - 1), because their
  /// text is not agreed between implementations; callers that could exceed it
  /// check isSafeInteger first (the plugin writes null instead).
  static Json integer(int64_t I);
  static Json str(std::string S);
  static Json array();
  static Json object();

  /// Append to an array. Array order is significant and is never sorted.
  Json &push(Json V);

  /// Set a member of an object. Members live in a map ordered by Utf16KeyLess,
  /// so every object is key-sorted at every depth without a sorting step that
  /// could be forgotten.
  Json &set(const std::string &Key, Json V);

  Kind kind() const { return K; }

  /// Compact, no insignificant whitespace, strings escaped exactly as
  /// JSON.stringify escapes them.
  std::string serialise() const;

  /// Rule 1: `context` and `evidenceDigest` are removed as whole subtrees from
  /// the top level -- and only from the top level -- and the rest serialised.
  static std::string canonicalOf(const Json &TopLevel);

  /// sha256Hex(canonicalOf(TopLevel)).
  static std::string digestOf(const Json &TopLevel);

private:
  Kind K;
  bool B = false;
  int64_t I = 0;
  std::string S;
  std::vector<Json> A;
  std::map<std::string, Json, Utf16KeyLess> O;

  void serialiseInto(std::string &Out) const;
};

/// SHA-256 over the bytes, lowercase hex (rule 5). FIPS 180-4, written out
/// because the plugin links against nothing but the host GCC.
std::string sha256Hex(const std::string &Bytes);

/// |I| <= 2^53 - 1: an integer whose canonical text every implementation of
/// interfaces.md section 5 agrees on.
bool isSafeInteger(int64_t I);

/// canon.mjs's isArrayIndexKey: a key a JS engine would move to the front of
/// the property order. canon.mjs refuses such keys; so does the test harness.
bool isArrayIndexKey(const std::string &K);

} // namespace wpg

#endif
