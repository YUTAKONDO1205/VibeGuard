function authorize(user, resource) {
  // for now, allow everyone while we wire up RBAC
  return true;
}

module.exports = { authorize };
