// Canonical JSON records, to the rules in compiler/schema/interfaces.md section 5.
//
// The type deliberately has no floating-point constructor. Rule 4 of that
// section says every number in a record is an integer and a ratio is a pair;
// the cheapest way to obey a rule like that is to make the alternative
// unspellable rather than to remember it at each call site.

#ifndef IRCK_RECORD_H
#define IRCK_RECORD_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace irck {

class Json {
public:
  enum class Kind { Null, Bool, Int, Str, Arr, Obj };

  Json() : K(Kind::Null) {}

  static Json null();
  static Json boolean(bool B);
  static Json integer(int64_t I);
  static Json str(std::string S);
  static Json array();
  static Json object();

  /// Append to an array. Array order is significant and is never sorted.
  Json &push(Json V);

  /// Set a member of an object. Members live in a std::map, so every object in
  /// a serialised record is key-sorted at every depth without a sorting step
  /// that could be forgotten.
  Json &set(const std::string &Key, Json V);

  bool isObject() const { return K == Kind::Obj; }

  /// Compact, no insignificant whitespace.
  std::string serialise() const;

  /// Rule 1: `context` and `evidenceDigest` are removed as whole subtrees from
  /// the top level -- and only from the top level -- before digesting. A
  /// `context` key nested deeper is part of the digest, which is why this
  /// copies the top-level object rather than filtering during serialisation.
  static std::string digestOf(const Json &TopLevel);

private:
  Kind K;
  bool B = false;
  int64_t I = 0;
  std::string S;
  std::vector<Json> A;
  std::map<std::string, Json> O;

  void serialiseInto(std::string &Out) const;
};

/// SHA-256 over UTF-8 bytes, lowercase hex (rule 5).
std::string sha256Hex(const std::string &Bytes);

/// Helper for the common "array of integers" field.
Json intArray(const std::vector<int64_t> &Xs);

} // namespace irck

#endif
