// Entry point of the sample service. Note what is NOT here: no authorization
// middleware is mounted, and no router is registered with a guard argument.
// Every route is registered as `router.<verb>(path, handler)` with a single
// handler, so the only place authorization can live is inside the handler
// bodies themselves — which is exactly the shape VG-SMELL-010 looks for.
import express from 'express';
import { userRouter } from './routes/user-routes';
import { billingRouter } from './routes/billing-routes';
import { reportRouter } from './routes/report-routes';

const app = express();

app.use(express.json());

app.use('/api/users', userRouter);
app.use('/api/billing', billingRouter);
app.use('/api/reports', reportRouter);

app.listen(Number(process.env.PORT ?? 3000));

export { app };
