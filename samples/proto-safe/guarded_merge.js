// Negative: safe merge variants. VG-INJ-020 must stay silent on all of them.

// Own-keys iteration + explicit __proto__/constructor guard.
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    if (source[key] && typeof source[key] === "object") {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// hasOwn-guarded recursive merge.
function extend(dst, src) {
  for (const key in src) {
    if (!Object.hasOwn(src, key)) continue;
    dst[key] = typeof src[key] === "object" ? extend(dst[key] || {}, src[key]) : src[key];
  }
  return dst;
}

// Null-prototype target — immune to pollution.
function toBag(src) {
  const out = Object.create(null);
  for (const key in src) {
    out[key] = src[key];
  }
  return out;
}

// Ordinary prototype-method assignment — not a prototype sink write.
function Widget() {}
Widget.prototype.render = function () {
  return this.state;
};

// Array index copy loop.
function copyArray(dst, src) {
  for (let i = 0; i < src.length; i++) {
    dst[i] = src[i];
  }
  return dst;
}

module.exports = { deepMerge, extend, toBag, Widget, copyArray };
