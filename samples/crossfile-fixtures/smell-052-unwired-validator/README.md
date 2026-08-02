# smell-052-unwired-validator/ — the canonical positive

The shape VG-SMELL-052 exists for. `middleware/validate-input.ts` is a complete,
correct Express validation middleware: it reads `req.query.q`, rejects anything
too long or carrying punctuation, and calls `next()`. It is exported. Its name
appears nowhere else in this directory — not at a route registration, not in an
import, not in a call.

Meanwhile `app.ts` registers two routes with no guard argument at all, and
`routes/search.ts` interpolates `req.query.q` straight into a SQL string. The
protection was generated, the request path it was generated for is live, and the
one line that connects them was never written.

**Expected: exactly one `VG-SMELL-052` finding, `high`** — `high` because the
untrusted value reaches a database query rather than only a response body.

`app.use(requestLogger)` is here on purpose. It is a `use` mount, not a route, so
it must **not** appear among the "this is where the validator should have been
applied" locations; a rule that treats every `app.use` as an unguarded route
would cite it. `app.use(express.json())` is the other half of that check — it has
no named handler at all.
