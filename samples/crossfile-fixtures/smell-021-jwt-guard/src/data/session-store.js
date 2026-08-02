const sessions = new Map();

async function findSession(id) {
  return sessions.get(id);
}

module.exports = { findSession };
