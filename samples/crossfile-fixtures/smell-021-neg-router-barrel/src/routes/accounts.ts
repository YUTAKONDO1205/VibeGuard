import { listAccounts } from '../services/list-accounts.js';

export const accountRoutes = {
  path: '/account',
  handlers: {
    async list(): Promise<unknown> {
      return listAccounts();
    },
  },
};
