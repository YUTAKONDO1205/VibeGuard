// Negative: the file name passes VG-SMELL-004's name gate, but the class is
// cohesive (a single crypto responsibility), so it must stay silent.
class CryptoUtils {
  static hashValue(x) {
    return sha256(x);
  }
  static encryptValue(x) {
    return cipher(x);
  }
  static decryptValue(x) {
    return decipher(x);
  }
  static hmacSign(x) {
    return hmac(x);
  }
  static deriveCipherKey(x) {
    return pbkdf2(x);
  }
}

module.exports = { CryptoUtils };
