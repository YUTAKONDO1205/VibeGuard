function readEnv(name, fallback) {
  return process.env[name] || fallback;
}

module.exports = { readEnv };
