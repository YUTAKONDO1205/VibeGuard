// Negative / adversarial: role comparisons appear ONLY inside comments. The
// comment-skipping in VG-SMELL-012 must keep this at zero findings.
// if (user.role === "admin") return true;
// if (user.role === "root") return true;
// if (user.role === "owner") return true;
function noop() {
  return 1;
}

module.exports = { noop };
