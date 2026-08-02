import express from 'express';
import * as guards from './security/guards';
import { listOrders } from './routes/orders';

const app = express();

app.use(express.json());

// Every function the module exports is mounted, in declaration order.
for (const guard of Object.values(guards)) {
  app.use(guard);
}

app.get('/orders', listOrders);

export { app };
