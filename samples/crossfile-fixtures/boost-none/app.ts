// Entry point. Three handlers, registered with no guard argument, so the
// authorization decision can only live inside the handler bodies — the same
// shape as `samples/crossfile-vulnerable`. The difference is everything AROUND
// the checks: no privilege word, no security path, no layer directory, no data
// mutation. See README.md.
import express from 'express';
import { listListings, getListing } from './catalog/listings';
import { getPriceBook } from './catalog/pricing';

const app = express();

app.use(express.json());

app.get('/listings', listListings);
app.get('/listings/:id', getListing);
app.get('/price-book', getPriceBook);

app.listen(Number(process.env.PORT ?? 3000));

export { app };
