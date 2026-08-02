import { adminIndex } from './routes/admin.js';
import { reportIndex } from './routes/reports.js';

export const routes = { 'GET /admin': adminIndex, 'GET /reports': reportIndex };
