#include "Record.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/SHA256.h"

#include <array>

namespace irck {

Json Json::null() { return Json(); }

Json Json::boolean(bool B) {
  Json J;
  J.K = Kind::Bool;
  J.B = B;
  return J;
}

Json Json::integer(int64_t I) {
  Json J;
  J.K = Kind::Int;
  J.I = I;
  return J;
}

Json Json::str(std::string S) {
  Json J;
  J.K = Kind::Str;
  J.S = std::move(S);
  return J;
}

Json Json::array() {
  Json J;
  J.K = Kind::Arr;
  return J;
}

Json Json::object() {
  Json J;
  J.K = Kind::Obj;
  return J;
}

Json &Json::push(Json V) {
  A.push_back(std::move(V));
  return *this;
}

Json &Json::set(const std::string &Key, Json V) {
  O[Key] = std::move(V);
  return *this;
}

static void escapeInto(const std::string &S, std::string &Out) {
  Out.push_back('"');
  for (unsigned char C : S) {
    switch (C) {
    case '"': Out += "\\\""; break;
    case '\\': Out += "\\\\"; break;
    case '\b': Out += "\\b"; break;
    case '\f': Out += "\\f"; break;
    case '\n': Out += "\\n"; break;
    case '\r': Out += "\\r"; break;
    case '\t': Out += "\\t"; break;
    default:
      if (C < 0x20) {
        static const char *Hex = "0123456789abcdef";
        Out += "\\u00";
        Out.push_back(Hex[(C >> 4) & 0xF]);
        Out.push_back(Hex[C & 0xF]);
      } else {
        Out.push_back(static_cast<char>(C));
      }
    }
  }
  Out.push_back('"');
}

void Json::serialiseInto(std::string &Out) const {
  switch (K) {
  case Kind::Null:
    Out += "null";
    return;
  case Kind::Bool:
    Out += (B ? "true" : "false");
    return;
  case Kind::Int:
    Out += std::to_string(I);
    return;
  case Kind::Str:
    escapeInto(S, Out);
    return;
  case Kind::Arr: {
    Out.push_back('[');
    bool First = true;
    for (const Json &E : A) {
      if (!First) Out.push_back(',');
      First = false;
      E.serialiseInto(Out);
    }
    Out.push_back(']');
    return;
  }
  case Kind::Obj: {
    Out.push_back('{');
    bool First = true;
    for (const auto &KV : O) {
      if (!First) Out.push_back(',');
      First = false;
      escapeInto(KV.first, Out);
      Out.push_back(':');
      KV.second.serialiseInto(Out);
    }
    Out.push_back('}');
    return;
  }
  }
}

std::string Json::serialise() const {
  std::string Out;
  serialiseInto(Out);
  return Out;
}

std::string Json::digestOf(const Json &TopLevel) {
  Json Stripped = TopLevel;
  if (Stripped.K == Kind::Obj) {
    Stripped.O.erase("context");
    Stripped.O.erase("evidenceDigest");
  }
  return sha256Hex(Stripped.serialise());
}

std::string sha256Hex(const std::string &Bytes) {
  llvm::SHA256 H;
  H.update(llvm::ArrayRef<uint8_t>(
      reinterpret_cast<const uint8_t *>(Bytes.data()), Bytes.size()));
  std::array<uint8_t, 32> D = H.final();
  return llvm::toHex(llvm::ArrayRef<uint8_t>(D.data(), D.size()),
                     /*LowerCase=*/true);
}

Json intArray(const std::vector<int64_t> &Xs) {
  Json A = Json::array();
  for (int64_t X : Xs) A.push(Json::integer(X));
  return A;
}

} // namespace irck
