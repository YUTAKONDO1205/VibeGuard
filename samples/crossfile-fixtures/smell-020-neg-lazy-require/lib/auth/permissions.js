// NEGATIVE fixture: the same project as `smell-020-cjs-require/` with the
// module-scope `require` moved inside the function that needs it. That is the
// documented Node remedy for a circular dependency — by the time `grantsFor`
// runs, both modules have finished loading — so reporting it would mean
// reporting the repair as the defect.
function grantsFor(subject) {
  const { registry } = require('../registry');
  return registry().grants[subject] || [];
}

function checkPermission(subject, action) {
  return grantsFor(subject).indexOf(action) !== -1;
}

module.exports = { checkPermission, grantsFor };
