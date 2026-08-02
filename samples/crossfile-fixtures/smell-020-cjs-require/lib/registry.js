const { checkPermission } = require('./auth/permissions');

function registry() {
  return { grants: { alice: ['read'] } };
}

function canRead(subject) {
  return checkPermission(subject, 'read');
}

module.exports = { registry, canRead };
