function makeOrder(id, accountId, totalCents) {
  return { id, accountId, totalCents };
}

module.exports = { makeOrder };
