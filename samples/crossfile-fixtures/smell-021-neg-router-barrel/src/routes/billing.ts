import { listInvoices } from '../services/list-invoices.js';

export const billingRoutes = {
  path: '/billing',
  handlers: {
    async list(): Promise<unknown> {
      return listInvoices();
    },
  },
};
