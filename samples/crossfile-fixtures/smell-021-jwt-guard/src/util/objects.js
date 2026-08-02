function pick(source, keys) {
  const out = {};
  for (const key of keys) out[key] = source[key];
  return out;
}

module.exports = { pick };
