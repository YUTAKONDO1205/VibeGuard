function makeSession(id, accountId) {
  return { id, accountId, expiresAt: '1970-01-02' };
}

module.exports = { makeSession };
