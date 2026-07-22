// VG-SMELL-004 positive: a SecurityUtils grab-bag mixing crypto, auth, validation,
// parsing, and business logic in one generic class.
class SecurityUtils {
  static hashPassword(p) {
    return bcrypt.hash(p, 10);
  }
  static generateJwt(user) {
    return jwt.sign(user, signingKey);
  }
  static sanitizeHtml(s) {
    return escapeHtml(s);
  }
  static validateEmail(e) {
    return /.+@.+\..+/.test(e);
  }
  static encryptFile(f) {
    return cipher.update(f);
  }
  static checkAdminRole(u) {
    return u.isAdmin === true;
  }
  static parseCsv(t) {
    return t.split(",");
  }
  static calculateTax(amount) {
    return amount * 0.1;
  }
}

module.exports = { SecurityUtils };
