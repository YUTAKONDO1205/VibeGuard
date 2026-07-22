// Negative: well-factored, short auth functions — VG-SMELL-003 must not fire.
function login(user, password) {
  if (!user) return null;
  if (!verifyPassword(user.hash, password)) return null;
  return issueToken(user);
}

function authorize(user, action) {
  return policy.can(user, action);
}

module.exports = { login, authorize };
