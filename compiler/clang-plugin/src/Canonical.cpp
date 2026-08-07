#include "Canonical.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdio>

using namespace llvm;

namespace intentgate {
namespace {

/// String escaping identical to `JSON.stringify`.
///
/// LLVM's own `json::Value` printer writes 0x08 and 0x0C as `` / ``
/// where `JSON.stringify` writes `\b` / `\f`. Both are valid JSON and both
/// parse to the same string, but they are different BYTES, and the digest is
/// over bytes. So this is written out rather than delegated.
void quote(raw_ostream &OS, StringRef S) {
  OS << '"';
  for (unsigned char C : S) {
    switch (C) {
    case '"':
      OS << "\\\"";
      continue;
    case '\\':
      OS << "\\\\";
      continue;
    case '\b':
      OS << "\\b";
      continue;
    case '\f':
      OS << "\\f";
      continue;
    case '\n':
      OS << "\\n";
      continue;
    case '\r':
      OS << "\\r";
      continue;
    case '\t':
      OS << "\\t";
      continue;
    default:
      break;
    }
    if (C < 0x20) {
      char Buf[8];
      std::snprintf(Buf, sizeof(Buf), "\\u%04x", static_cast<unsigned>(C));
      OS << Buf;
    } else {
      // >= 0x20 passes through as raw bytes, which for UTF-8 input reproduces
      // `JSON.stringify`'s default (it does not escape non-ASCII either).
      OS << static_cast<char>(C);
    }
  }
  OS << '"';
}

bool emit(const json::Value &V, raw_ostream &OS, std::string &Err) {
  switch (V.kind()) {
  case json::Value::Null:
    OS << "null";
    return true;
  case json::Value::Boolean:
    OS << (*V.getAsBoolean() ? "true" : "false");
    return true;
  case json::Value::Number: {
    // Rule 4. `getAsInteger` succeeds only for a value that is exactly an
    // integer, so a 3.0 stored as a double is accepted (it IS an integer) and a
    // 0.75 is refused (it is not).
    if (std::optional<int64_t> I = V.getAsInteger()) {
      OS << *I;
      return true;
    }
    std::string Rendered;
    raw_string_ostream RS(Rendered);
    RS << V;
    Err = "non-integer number in record: " + RS.str() +
          " (interfaces.md §5.4 — a ratio is a pair {\"num\":n,\"den\":d})";
    return false;
  }
  case json::Value::String:
    quote(OS, *V.getAsString());
    return true;
  case json::Value::Array: {
    const json::Array &A = *V.getAsArray();
    OS << '[';
    bool First = true;
    for (const json::Value &E : A) {
      if (!First)
        OS << ',';
      First = false;
      if (!emit(E, OS, Err))
        return false;
    }
    OS << ']';
    return true;
  }
  case json::Value::Object: {
    const json::Object &O = *V.getAsObject();
    // json::Object is a DenseMap; its iteration order is unspecified and
    // changes with insertion history. Sorting here is what makes the digest a
    // function of the content rather than of how the object was built.
    SmallVector<StringRef, 16> Keys;
    for (const auto &KV : O)
      Keys.push_back(KV.first);
    std::sort(Keys.begin(), Keys.end(), [](StringRef A, StringRef B) {
      return A.compare(B) < 0; // byte order; every key emitted here is ASCII
    });
    OS << '{';
    bool First = true;
    for (StringRef K : Keys) {
      if (!First)
        OS << ',';
      First = false;
      quote(OS, K);
      OS << ':';
      if (!emit(*O.get(K), OS, Err))
        return false;
    }
    OS << '}';
    return true;
  }
  }
  Err = "unreachable json kind";
  return false;
}

} // namespace

bool canonicalize(const json::Value &V, std::string &Out, std::string &Err) {
  Out.clear();
  raw_string_ostream OS(Out);
  bool Ok = emit(V, OS, Err);
  OS.flush();
  if (!Ok)
    Out.clear();
  return Ok;
}

std::string sha256Hex(StringRef Bytes) {
  SHA256 H;
  H.update(ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(Bytes.data()), Bytes.size()));
  std::array<uint8_t, 32> D = H.final();
  std::string Hex;
  Hex.reserve(64);
  for (uint8_t B : D) {
    char Buf[3];
    std::snprintf(Buf, sizeof(Buf), "%02x", static_cast<unsigned>(B));
    Hex += Buf;
  }
  return Hex;
}

bool sha256File(StringRef Path, std::string &OutHex) {
  ErrorOr<std::unique_ptr<MemoryBuffer>> Buf = MemoryBuffer::getFile(Path, /*IsText=*/false);
  if (!Buf)
    return false;
  OutHex = sha256Hex((*Buf)->getBuffer());
  return true;
}

bool evidenceDigest(const json::Object &Top, std::string &OutHex, std::string &Err) {
  json::Object Copy;
  for (const auto &KV : Top) {
    StringRef K = KV.first;
    if (K == "context" || K == "evidenceDigest")
      continue; // rule 1: whole subtrees, top level only
    Copy[K] = KV.second;
  }
  std::string Canon;
  if (!canonicalize(json::Value(std::move(Copy)), Canon, Err))
    return false;
  OutHex = sha256Hex(Canon);
  return true;
}

} // namespace intentgate
