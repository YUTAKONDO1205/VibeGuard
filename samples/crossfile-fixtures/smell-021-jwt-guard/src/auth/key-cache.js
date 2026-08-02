const { config } = require('../config/config');

const keys = new Map();

async function publicKeyFor(kid) {
  if (!keys.has(kid)) keys.set(kid, `${config.issuer}#${kid}`);
  return keys.get(kid);
}

module.exports = { publicKeyFor };
