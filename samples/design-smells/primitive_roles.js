// VG-SMELL-012 positive: role decided by hardcoded string literals, no enum/policy.
function canAccess(user, req, account) {
  if (user.role === "admin") return grantAll();
  if (req.user.role == "owner") return grantOwner();
  if (account.userType === "manager") return grantSome();
  if (account.permission === "editor") return grantEdit();
  return false;
}

module.exports = { canAccess };
