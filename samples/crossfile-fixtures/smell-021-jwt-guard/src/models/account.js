function makeAccount(id, email) {
  return { id, email, createdAt: '1970-01-01' };
}

module.exports = { makeAccount };
