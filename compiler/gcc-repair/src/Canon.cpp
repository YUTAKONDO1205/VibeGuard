#include "Canon.h"

#include <array>
#include <cstring>

namespace wpg {

namespace {

/// The UTF-16 code units of a UTF-8 string, the way a JS string holds it.
/// Malformed bytes become one unit each (see Utf16KeyLess).
std::vector<uint16_t> utf16Units(const std::string &S) {
  std::vector<uint16_t> U;
  U.reserve(S.size());
  const auto *P = reinterpret_cast<const unsigned char *>(S.data());
  const size_t N = S.size();
  size_t I = 0;
  while (I < N) {
    const unsigned char C = P[I];
    uint32_t CP = 0;
    size_t Len = 0;
    if (C < 0x80) { CP = C; Len = 1; }
    else if ((C & 0xE0) == 0xC0) { CP = C & 0x1F; Len = 2; }
    else if ((C & 0xF0) == 0xE0) { CP = C & 0x0F; Len = 3; }
    else if ((C & 0xF8) == 0xF0) { CP = C & 0x07; Len = 4; }
    bool Ok = Len > 0 && I + Len <= N;
    for (size_t K = 1; Ok && K < Len; ++K) {
      if ((P[I + K] & 0xC0) != 0x80) Ok = false;
      else CP = (CP << 6) | (P[I + K] & 0x3F);
    }
    if (!Ok) {
      U.push_back(C);
      I += 1;
      continue;
    }
    if (CP >= 0x10000) {
      CP -= 0x10000;
      U.push_back(static_cast<uint16_t>(0xD800 + (CP >> 10)));
      U.push_back(static_cast<uint16_t>(0xDC00 + (CP & 0x3FF)));
    } else {
      U.push_back(static_cast<uint16_t>(CP));
    }
    I += Len;
  }
  return U;
}

void escapeInto(const std::string &S, std::string &Out) {
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

// --------------------------------------------------------------- SHA-256 ----

const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t X, unsigned N) { return (X >> N) | (X << (32 - N)); }

void compress(std::array<uint32_t, 8> &H, const unsigned char *Block) {
  uint32_t W[64];
  for (int T = 0; T < 16; ++T)
    W[T] = (uint32_t(Block[4 * T]) << 24) | (uint32_t(Block[4 * T + 1]) << 16) |
           (uint32_t(Block[4 * T + 2]) << 8) | uint32_t(Block[4 * T + 3]);
  for (int T = 16; T < 64; ++T) {
    const uint32_t S0 = rotr(W[T - 15], 7) ^ rotr(W[T - 15], 18) ^ (W[T - 15] >> 3);
    const uint32_t S1 = rotr(W[T - 2], 17) ^ rotr(W[T - 2], 19) ^ (W[T - 2] >> 10);
    W[T] = W[T - 16] + S0 + W[T - 7] + S1;
  }
  uint32_t A = H[0], B = H[1], C = H[2], D = H[3], E = H[4], F = H[5], G = H[6], Hh = H[7];
  for (int T = 0; T < 64; ++T) {
    const uint32_t S1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
    const uint32_t Ch = (E & F) ^ (~E & G);
    const uint32_t T1 = Hh + S1 + Ch + K256[T] + W[T];
    const uint32_t S0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
    const uint32_t Maj = (A & B) ^ (A & C) ^ (B & C);
    const uint32_t T2 = S0 + Maj;
    Hh = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
  }
  H[0] += A; H[1] += B; H[2] += C; H[3] += D;
  H[4] += E; H[5] += F; H[6] += G; H[7] += Hh;
}

} // namespace

bool Utf16KeyLess::operator()(const std::string &A, const std::string &B) const {
  // Fast path: two ASCII-only keys (every key this plugin writes) compare as
  // bytes, which for ASCII is the same order as code units.
  bool Ascii = true;
  for (unsigned char C : A) if (C >= 0x80) { Ascii = false; break; }
  if (Ascii)
    for (unsigned char C : B) if (C >= 0x80) { Ascii = false; break; }
  if (Ascii) return A < B;
  const std::vector<uint16_t> UA = utf16Units(A), UB = utf16Units(B);
  return UA < UB;
}

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

std::string Json::canonicalOf(const Json &TopLevel) {
  if (TopLevel.K != Kind::Obj) return TopLevel.serialise();
  Json Stripped = TopLevel;
  Stripped.O.erase("context");
  Stripped.O.erase("evidenceDigest");
  return Stripped.serialise();
}

std::string Json::digestOf(const Json &TopLevel) {
  return sha256Hex(canonicalOf(TopLevel));
}

std::string sha256Hex(const std::string &Bytes) {
  std::array<uint32_t, 8> H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const auto *P = reinterpret_cast<const unsigned char *>(Bytes.data());
  const size_t N = Bytes.size();
  size_t Off = 0;
  for (; Off + 64 <= N; Off += 64) compress(H, P + Off);

  // Padding: 0x80, zeros, then the message length in bits, big-endian, so
  // that the total is a multiple of 64 bytes.
  unsigned char Tail[128];
  std::memset(Tail, 0, sizeof Tail);
  const size_t Rest = N - Off;
  if (Rest) std::memcpy(Tail, P + Off, Rest);
  Tail[Rest] = 0x80;
  const size_t TailLen = (Rest + 1 + 8 <= 64) ? 64 : 128;
  const uint64_t Bits = static_cast<uint64_t>(N) * 8;
  for (int K = 0; K < 8; ++K)
    Tail[TailLen - 1 - K] = static_cast<unsigned char>(Bits >> (8 * K));
  compress(H, Tail);
  if (TailLen == 128) compress(H, Tail + 64);

  static const char *Hex = "0123456789abcdef";
  std::string Out;
  Out.reserve(64);
  for (uint32_t W : H)
    for (int Shift = 28; Shift >= 0; Shift -= 4) Out.push_back(Hex[(W >> Shift) & 0xF]);
  return Out;
}

bool isSafeInteger(int64_t I) {
  const int64_t Max = (int64_t(1) << 53) - 1;
  return I >= -Max && I <= Max;
}

bool isArrayIndexKey(const std::string &K) {
  if (K.empty() || K.size() > 10) return false;
  if (K.size() > 1 && K[0] == '0') return false;
  for (char C : K)
    if (C < '0' || C > '9') return false;
  // < 2^32 - 1, the language's own bound for an array index.
  return std::stoull(K) < 4294967295ULL;
}

} // namespace wpg
