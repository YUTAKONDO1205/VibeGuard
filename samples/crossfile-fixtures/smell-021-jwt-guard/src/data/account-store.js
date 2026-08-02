const accounts = new Map();

async function findAccount(id) {
  return accounts.get(id);
}

module.exports = { findAccount };
