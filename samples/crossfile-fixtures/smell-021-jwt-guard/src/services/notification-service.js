const { log } = require('../util/log');

function notify(accountId, message) {
  log('notify', `${accountId}:${message}`);
}

module.exports = { notify };
