import { adminReports } from './routes/admin-routes.js';
import { createOrder } from './routes/order-routes.js';
import { myReports } from './routes/report-routes.js';

export const routes = {
  'GET /admin/reports': adminReports,
  'POST /orders': createOrder,
  'GET /reports': myReports,
};
