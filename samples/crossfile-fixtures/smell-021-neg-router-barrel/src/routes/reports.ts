import { listReports } from '../services/list-reports.js';

export const reportRoutes = {
  path: '/report',
  handlers: {
    async list(): Promise<unknown> {
      return listReports();
    },
  },
};
