// Negative: roles are a frozen constant set; comparisons use the constants, not
// hardcoded string literals. VG-SMELL-012 must stay silent (constant layer +
// Object.freeze veto).
const Roles = Object.freeze({ ADMIN: "admin", OWNER: "owner", MEMBER: "member" });

function canAccess(user) {
  if (user.role === Roles.ADMIN) return true;
  if (user.role === Roles.OWNER) return true;
  if (user.role === Roles.MEMBER) return false;
  return false;
}

module.exports = { Roles, canAccess };
