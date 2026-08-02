import { listOrders } from '../services/list-orders.js';

export const orderRoutes = {
  path: '/order',
  handlers: {
    async list(): Promise<unknown> {
      return listOrders();
    },
  },
};
