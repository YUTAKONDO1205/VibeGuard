import { healthReport } from '../services/health-report.js';

export const healthRoutes = {
  path: '/health',
  handlers: {
    async list(): Promise<unknown> {
      return healthReport();
    },
  },
};
