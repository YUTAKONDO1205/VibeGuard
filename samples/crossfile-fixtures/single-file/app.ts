import express from 'express';
import { adminRouter } from './admin-controller';

const app = express();
app.use('/api/admin', adminRouter);

export { app };
