// Calibrates src/Canon.cpp -- the canonical JSON writer and SHA-256 the GCC
// plugin seals its records with -- against the shared calibration
// compiler/evidence/testdata/digest-vectors.json, whose expected values were
// produced by the independent reference implementation, never by hand.
//
//   canon-vectors <path to digest-vectors.json>
//
// Exit 0: every vector reproduced (canonical text and digest), every mustFail
// input refused, and the extra cases below held. Exit 2: something disagreed
// (listed). Exit 3: the vector file could not be read or parsed.
//
// The file is parsed by a small JSON reader written here, into a value type
// that CAN hold a float, an unsafe integer and an array-index key -- because the
// mustFail vectors contain all three, and rule 1 (drop `context` first) has to
// be applied before rule 4 (refuse non-integers) for the vector
// `context-is-dropped-before-the-integer-rule` to pass. Only the conversion to
// wpg::Json refuses, which is where the plugin's own writer would.

#include "Canon.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Value {
  enum class K { Null, Bool, Int, Float, Str, Arr, Obj } Kind = K::Null;
  bool B = false;
  int64_t I = 0;
  bool UnsafeInt = false; // an integer literal outside +-(2^53 - 1)
  std::string S;          // also the literal text of a Float or unsafe integer
  std::vector<Value> A;
  std::vector<std::pair<std::string, Value>> O;
};

class Parser {
public:
  explicit Parser(const std::string &T) : T(T) {}

  Value parseDocument() {
    Value V = parseValue();
    ws();
    if (P != T.size()) fail("trailing text");
    return V;
  }

private:
  const std::string &T;
  size_t P = 0;

  [[noreturn]] void fail(const std::string &Why) {
    throw std::runtime_error(Why + " at offset " + std::to_string(P));
  }
  void ws() {
    while (P < T.size() && (T[P] == ' ' || T[P] == '\t' || T[P] == '\n' || T[P] == '\r')) ++P;
  }
  bool eat(char C) {
    ws();
    if (P < T.size() && T[P] == C) { ++P; return true; }
    return false;
  }
  void expect(char C) {
    if (!eat(C)) fail(std::string("expected '") + C + "'");
  }

  static void appendUtf8(uint32_t CP, std::string &Out) {
    if (CP < 0x80) Out.push_back(char(CP));
    else if (CP < 0x800) { Out.push_back(char(0xC0 | (CP >> 6))); Out.push_back(char(0x80 | (CP & 0x3F))); }
    else if (CP < 0x10000) {
      Out.push_back(char(0xE0 | (CP >> 12)));
      Out.push_back(char(0x80 | ((CP >> 6) & 0x3F)));
      Out.push_back(char(0x80 | (CP & 0x3F)));
    } else {
      Out.push_back(char(0xF0 | (CP >> 18)));
      Out.push_back(char(0x80 | ((CP >> 12) & 0x3F)));
      Out.push_back(char(0x80 | ((CP >> 6) & 0x3F)));
      Out.push_back(char(0x80 | (CP & 0x3F)));
    }
  }

  uint32_t hex4() {
    if (P + 4 > T.size()) fail("short \\u escape");
    uint32_t V = 0;
    for (int K = 0; K < 4; ++K) {
      const char C = T[P++];
      V <<= 4;
      if (C >= '0' && C <= '9') V |= uint32_t(C - '0');
      else if (C >= 'a' && C <= 'f') V |= uint32_t(C - 'a' + 10);
      else if (C >= 'A' && C <= 'F') V |= uint32_t(C - 'A' + 10);
      else fail("bad hex digit");
    }
    return V;
  }

  std::string parseString() {
    ws();
    if (P >= T.size() || T[P] != '"') fail("expected a string");
    ++P;
    std::string Out;
    while (true) {
      if (P >= T.size()) fail("unterminated string");
      const char C = T[P++];
      if (C == '"') break;
      if (C != '\\') { Out.push_back(C); continue; }
      if (P >= T.size()) fail("dangling escape");
      const char E = T[P++];
      switch (E) {
      case '"': Out.push_back('"'); break;
      case '\\': Out.push_back('\\'); break;
      case '/': Out.push_back('/'); break;
      case 'b': Out.push_back('\b'); break;
      case 'f': Out.push_back('\f'); break;
      case 'n': Out.push_back('\n'); break;
      case 'r': Out.push_back('\r'); break;
      case 't': Out.push_back('\t'); break;
      case 'u': {
        uint32_t CP = hex4();
        if (CP >= 0xD800 && CP <= 0xDBFF && P + 6 <= T.size() && T[P] == '\\' && T[P + 1] == 'u') {
          P += 2;
          const uint32_t Lo = hex4();
          if (Lo < 0xDC00 || Lo > 0xDFFF) fail("unpaired surrogate");
          CP = 0x10000 + ((CP - 0xD800) << 10) + (Lo - 0xDC00);
        }
        appendUtf8(CP, Out);
        break;
      }
      default: fail("bad escape");
      }
    }
    return Out;
  }

  Value parseNumber() {
    const size_t Start = P;
    if (T[P] == '-') ++P;
    while (P < T.size() && T[P] >= '0' && T[P] <= '9') ++P;
    bool IsFloat = false;
    if (P < T.size() && T[P] == '.') {
      IsFloat = true;
      ++P;
      while (P < T.size() && T[P] >= '0' && T[P] <= '9') ++P;
    }
    if (P < T.size() && (T[P] == 'e' || T[P] == 'E')) {
      IsFloat = true;
      ++P;
      if (P < T.size() && (T[P] == '+' || T[P] == '-')) ++P;
      while (P < T.size() && T[P] >= '0' && T[P] <= '9') ++P;
    }
    Value V;
    V.S = T.substr(Start, P - Start);
    if (IsFloat) {
      V.Kind = Value::K::Float;
      return V;
    }
    V.Kind = Value::K::Int;
    const bool Neg = V.S[0] == '-';
    const std::string Digits = Neg ? V.S.substr(1) : V.S;
    if (Digits.empty()) fail("bad number");
    if (Digits.size() > 16) {
      V.UnsafeInt = true;
      return V;
    }
    const int64_t Mag = std::stoll(Digits);
    V.I = Neg ? -Mag : Mag;
    V.UnsafeInt = !wpg::isSafeInteger(V.I);
    return V;
  }

  Value parseValue() {
    ws();
    if (P >= T.size()) fail("unexpected end");
    const char C = T[P];
    Value V;
    if (C == '{') {
      ++P;
      V.Kind = Value::K::Obj;
      if (eat('}')) return V;
      do {
        std::string K = parseString();
        expect(':');
        V.O.emplace_back(std::move(K), parseValue());
      } while (eat(','));
      expect('}');
      return V;
    }
    if (C == '[') {
      ++P;
      V.Kind = Value::K::Arr;
      if (eat(']')) return V;
      do V.A.push_back(parseValue());
      while (eat(','));
      expect(']');
      return V;
    }
    if (C == '"') {
      V.Kind = Value::K::Str;
      V.S = parseString();
      return V;
    }
    if (T.compare(P, 4, "true") == 0) { P += 4; V.Kind = Value::K::Bool; V.B = true; return V; }
    if (T.compare(P, 5, "false") == 0) { P += 5; V.Kind = Value::K::Bool; V.B = false; return V; }
    if (T.compare(P, 4, "null") == 0) { P += 4; return V; }
    if (C == '-' || (C >= '0' && C <= '9')) return parseNumber();
    fail("unexpected character");
  }
};

/// Refuses exactly what canon.mjs refuses; everything else becomes wpg::Json.
wpg::Json toJson(const Value &V, const std::string &Where) {
  switch (V.Kind) {
  case Value::K::Null: return wpg::Json::null();
  case Value::K::Bool: return wpg::Json::boolean(V.B);
  case Value::K::Float: throw std::runtime_error("non-integer number " + V.S + " at " + Where);
  case Value::K::Int:
    if (V.UnsafeInt) throw std::runtime_error("integer outside the exact range " + V.S + " at " + Where);
    return wpg::Json::integer(V.I);
  case Value::K::Str: return wpg::Json::str(V.S);
  case Value::K::Arr: {
    wpg::Json A = wpg::Json::array();
    for (size_t K = 0; K < V.A.size(); ++K)
      A.push(toJson(V.A[K], Where + "[" + std::to_string(K) + "]"));
    return A;
  }
  case Value::K::Obj: {
    wpg::Json O = wpg::Json::object();
    for (const auto &KV : V.O) {
      if (wpg::isArrayIndexKey(KV.first))
        throw std::runtime_error("array-index key \"" + KV.first + "\" at " + Where);
      O.set(KV.first, toJson(KV.second, Where + "." + KV.first));
    }
    return O;
  }
  }
  return wpg::Json::null();
}

/// Rule 1 before everything else: the top-level `context` and
/// `evidenceDigest` go as whole subtrees, whatever they hold.
wpg::Json recordToJson(const Value &V) {
  if (V.Kind != Value::K::Obj) return toJson(V, "$");
  Value Stripped = V;
  Stripped.O.clear();
  for (const auto &KV : V.O)
    if (KV.first != "context" && KV.first != "evidenceDigest") Stripped.O.push_back(KV);
  return toJson(Stripped, "$");
}

const Value *member(const Value &Obj, const std::string &Key) {
  for (const auto &KV : Obj.O)
    if (KV.first == Key) return &KV.second;
  return nullptr;
}

} // namespace

int main(int Argc, char **Argv) {
  if (Argc != 2) {
    std::fprintf(stderr, "usage: canon-vectors <digest-vectors.json>\n");
    return 3;
  }
  std::ifstream In(Argv[1], std::ios::binary);
  if (!In) {
    std::fprintf(stderr, "canon-vectors: cannot read %s\n", Argv[1]);
    return 3;
  }
  std::stringstream Buf;
  Buf << In.rdbuf();
  const std::string Text = Buf.str();

  Value Doc;
  try {
    Doc = Parser(Text).parseDocument();
  } catch (const std::exception &E) {
    std::fprintf(stderr, "canon-vectors: the vector file does not parse: %s\n", E.what());
    return 3;
  }
  const Value *Vectors = member(Doc, "vectors");
  const Value *MustFail = member(Doc, "mustFail");
  if (!Vectors || Vectors->Kind != Value::K::Arr || Vectors->A.empty() || !MustFail ||
      MustFail->Kind != Value::K::Arr || MustFail->A.empty()) {
    std::fprintf(stderr, "canon-vectors: no vectors or no mustFail list; nothing was calibrated\n");
    return 3;
  }

  int Bad = 0, Held = 0;
  auto Report = [&](bool Ok, const std::string &Name, const std::string &Detail) {
    if (Ok) {
      ++Held;
    } else {
      ++Bad;
      std::printf("DISAGREES %s: %s\n", Name.c_str(), Detail.c_str());
    }
  };

  for (const Value &V : Vectors->A) {
    const Value *Name = member(V, "name");
    const Value *Input = member(V, "input");
    const Value *Canon = member(V, "canonicalText");
    const Value *Digest = member(V, "digest");
    const std::string N = Name ? Name->S : "?";
    if (!Input || !Canon || !Digest) {
      Report(false, N, "vector lacks input, canonicalText or digest");
      continue;
    }
    try {
      const wpg::Json J = recordToJson(*Input);
      const std::string Got = wpg::Json::canonicalOf(J);
      const std::string Dig = wpg::Json::digestOf(J);
      Report(Got == Canon->S, N, "canonical text " + Got + " expected " + Canon->S);
      Report(Dig == Digest->S, N + " (digest)", Dig + " expected " + Digest->S);
    } catch (const std::exception &E) {
      Report(false, N, std::string("refused: ") + E.what());
    }
  }

  for (const Value &V : MustFail->A) {
    const Value *Name = member(V, "name");
    const Value *Input = member(V, "input");
    const std::string N = Name ? Name->S : "?";
    if (!Input) {
      Report(false, N, "mustFail entry lacks input");
      continue;
    }
    bool Refused = false;
    try {
      (void)recordToJson(*Input);
    } catch (const std::exception &) {
      Refused = true;
    }
    Report(Refused, N + " (mustFail)", "was accepted");
  }

  // --- extra cases, expected values from canon.mjs / node:crypto -------------
  {
    // Separates UTF-16 code-unit order (canon.mjs) from UTF-8 byte order:
    // U+1F600 is a surrogate pair (0xD83D ...) and sorts before U+FF01 in
    // UTF-16; its UTF-8 lead byte 0xF0 would sort it after (0xEF).
    wpg::Json J = wpg::Json::object();
    J.set("\xEF\xBC\x81", wpg::Json::integer(1));     // U+FF01
    J.set("\xF0\x9F\x98\x80", wpg::Json::integer(2)); // U+1F600
    J.set("z", wpg::Json::integer(3));
    J.set("\xC3\xA9", wpg::Json::integer(4));          // U+00E9
    const std::string Want = "{\"z\":3,\"\xC3\xA9\":4,\"\xF0\x9F\x98\x80\":2,\"\xEF\xBC\x81\":1}";
    Report(wpg::Json::canonicalOf(J) == Want, "utf16-order-astral-before-fullwidth",
           wpg::Json::canonicalOf(J));
    Report(wpg::Json::digestOf(J) ==
               "61de167b353bccbdf6aa0a3245e30f7bea2fe594dc749bbc6c16ff4c76fcaea1",
           "utf16-order-astral-before-fullwidth (digest)", wpg::Json::digestOf(J));
  }
  {
    // The toolchain block of every WipePinGcc record built against 13.3.0.
    wpg::Json J = wpg::Json::object();
    J.set("gcc", wpg::Json::str("13.3.0"));
    J.set("packages", wpg::Json::array().push(wpg::Json::object()
                                                  .set("name", wpg::Json::str("gcc"))
                                                  .set("version", wpg::Json::str("13.3.0"))));
    Report(wpg::Json::digestOf(J) ==
               "59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0",
           "toolchain-gcc-13.3.0", wpg::Json::digestOf(J));
  }
  {
    // SHA-256 at the padding boundaries (55/56 and 119/120 bytes change the
    // number of blocks), from node:crypto.
    const std::pair<size_t, const char *> Cases[] = {
        {0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {1, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
        {55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
        {56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
        {63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
        {64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
        {65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
        {119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"},
        {120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"},
        {1000, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"},
    };
    for (const auto &C : Cases) {
      const std::string Got = wpg::sha256Hex(std::string(C.first, 'a'));
      Report(Got == C.second, "sha256 of " + std::to_string(C.first) + " x 'a'", Got);
    }
  }
  {
    // JSON.stringify's escaping of the characters a module basename could hold.
    wpg::Json J = wpg::Json::object();
    J.set("s", wpg::Json::str(std::string("a\x01" "b\x7f" "c/\"\\\t", 9)));
    const std::string Want = "{\"s\":\"a\\u0001b\x7f" "c/\\\"\\\\\\t\"}";
    Report(J.serialise() == Want, "escaping", J.serialise());
  }

  std::printf("canon-vectors: %zu vectors, %zu mustFail, %d checks held, %d disagreed\n",
              Vectors->A.size(), MustFail->A.size(), Held, Bad);
  return Bad ? 2 : 0;
}
