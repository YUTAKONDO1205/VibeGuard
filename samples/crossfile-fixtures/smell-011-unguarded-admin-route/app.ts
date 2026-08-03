import express from 'express';
import { adminRouter } from './routes/admin-routes';
import { tenantRouter } from './routes/tenant-routes';

const app = express();

app.use(express.json());

// Plain router mounts: no guard is attached to either, so neither says anything
// about what is protected.
app.use('/api/admin', adminRouter);
app.use('/api/tenant', tenantRouter);

export { app };
