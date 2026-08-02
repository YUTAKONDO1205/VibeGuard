import { listWebhooks } from '../services/list-webhooks.js';

export const webhookRoutes = {
  path: '/webhook',
  handlers: {
    async list(): Promise<unknown> {
      return listWebhooks();
    },
  },
};
