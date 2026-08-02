// Positive fixture for VG-SMELL-020 — the CommonJS arm.
//
// The `require` is at module scope, so it runs at load time and the cycle is
// real. `smell-020-neg-lazy-require/` is the same project with the call moved
// inside the function, which is the documented repair.
const { registry } = require('../registry');

const GRANTS = registry().grants;

function checkPermission(subject, action) {
  return (GRANTS[subject] || []).indexOf(action) !== -1;
}

module.exports = { checkPermission, GRANTS };
