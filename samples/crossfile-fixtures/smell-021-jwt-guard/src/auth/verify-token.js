const jwt = require('jsonwebtoken');
const { config } = require('../config/config');
const { publicKeyFor } = require('../auth/key-cache');
const { findSession } = require('../data/session-store');
const { findAccount } = require('../data/account-store');
const { isRevoked } = require('../data/revocation-list');
const { bumpCounter } = require('../telemetry/counters');
const { log } = require('../util/log');
const { HttpError } = require('../util/http-error');

async function verifyToken(rawToken, audience) {
  const header = jwt.decode(rawToken, { complete: true });
  if (!header) throw new HttpError(401, 'malformed token');

  const key = await publicKeyFor(header.header.kid);
  const claims = jwt.verify(rawToken, key, { audience, issuer: config.issuer });

  if (await isRevoked(claims.jti)) {
    bumpCounter('token.revoked');
    throw new HttpError(401, 'revoked token');
  }

  const session = await findSession(claims.sid);
  if (!session) {
    log('session missing for token', claims.sid);
    throw new HttpError(401, 'session expired');
  }

  const account = await findAccount(claims.sub);
  bumpCounter('token.verified');
  return { account, session, claims };
}

module.exports = { verifyToken };
