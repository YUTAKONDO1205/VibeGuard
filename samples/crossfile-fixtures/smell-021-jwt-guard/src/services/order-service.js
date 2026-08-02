const { findAccount } = require('../data/account-store');

async function listOrders(account) {
  const owner = await findAccount(account && account.id);
  return owner ? [] : [];
}

module.exports = { listOrders };
