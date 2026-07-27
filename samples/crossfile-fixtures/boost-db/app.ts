// Entry point. Same registration shape as `boost-none/app.ts` — three handlers,
// no guard argument — so this directory differs from that one in exactly one
// respect: each handler writes to a data store. See README.md.
import express from 'express';
import { renameListing, retireListing } from './catalog/listings';
import { repriceListing } from './catalog/pricing';

const app = express();

app.use(express.json());

app.post('/listings/:id/rename', renameListing);
app.post('/listings/:id/retire', retireListing);
app.post('/listings/:id/reprice', repriceListing);

app.listen(Number(process.env.PORT ?? 3000));

export { app };
