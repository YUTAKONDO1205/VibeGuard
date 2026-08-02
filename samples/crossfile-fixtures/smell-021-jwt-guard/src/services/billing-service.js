const { config } = require('../config/config');

function invoiceFor(accountId) {
  return { accountId, issuer: config.issuer, lines: [] };
}

module.exports = { invoiceFor };
