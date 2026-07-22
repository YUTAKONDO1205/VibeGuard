// VG-INJ-020 positive: recursive unguarded for-in merge (branch B) plus a
// literal __proto__ write (branch A).
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object") {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function applyOverride(obj, patch) {
  obj.__proto__.polluted = patch;
  return obj;
}

module.exports = { deepMerge, applyOverride };
