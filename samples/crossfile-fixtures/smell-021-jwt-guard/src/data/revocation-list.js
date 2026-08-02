const revoked = new Set();

async function isRevoked(jti) {
  return revoked.has(jti);
}

module.exports = { isRevoked };
