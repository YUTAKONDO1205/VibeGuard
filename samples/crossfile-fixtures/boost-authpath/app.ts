// Entry point. Same registration shape as `boost-none/app.ts` — three handlers,
// no guard argument — so this directory differs from that one in exactly one
// respect: where the handlers live. See README.md.
import express from 'express';
import { sessionRouter } from './auth/sessions';
import { deviceRouter } from './auth/devices';

const app = express();

app.use(express.json());

app.use('/auth/sessions', sessionRouter);
app.use('/auth/devices', deviceRouter);

app.listen(Number(process.env.PORT ?? 3000));

export { app };
