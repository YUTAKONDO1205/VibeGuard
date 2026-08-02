const { verifyToken } = require('../auth/verify-token');

async function me(req) {
  const result = await verifyToken(req.headers.authorization, 'api');
  return { status: 200, body: result.account };
}

module.exports = { me };
