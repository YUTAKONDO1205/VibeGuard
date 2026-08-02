const { verifyToken } = require('../auth/verify-token');
const { listOrders } = require('../services/order-service');

async function orders(req) {
  const result = await verifyToken(req.headers.authorization, 'api');
  return { status: 200, body: await listOrders(result.account) };
}

module.exports = { orders };
