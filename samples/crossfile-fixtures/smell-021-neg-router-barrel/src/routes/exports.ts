import { listExports } from '../services/list-exports.js';

export const exportRoutes = {
  path: '/export',
  handlers: {
    async list(): Promise<unknown> {
      return listExports();
    },
  },
};
