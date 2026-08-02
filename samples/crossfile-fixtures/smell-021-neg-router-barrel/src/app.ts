import { mountRoutes } from './routes/index.js';

export function createApp(): unknown {
  return { routes: mountRoutes() };
}
