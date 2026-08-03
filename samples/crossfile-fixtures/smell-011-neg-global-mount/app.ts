import express from 'express';
import { requireLogin } from './middleware/require-login';
import { accountRouter } from './routes/account-routes';

const app = express();

app.use(express.json());

// The layered design: authentication for everything, authorization per route.
// Whether this line runs before the router below is a fact about execution
// order, and execution order is not what a lexical reading of a file gives you.
app.use(requireLogin);

app.use('/api', accountRouter);

export { app };
