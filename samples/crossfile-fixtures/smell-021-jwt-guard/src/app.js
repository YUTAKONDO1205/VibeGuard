const { me } = require('./routes/me');
const { orders } = require('./routes/orders');
const { health } = require('./routes/health');

const routes = { 'GET /me': me, 'GET /orders': orders, 'GET /health': health };

module.exports = { routes };
