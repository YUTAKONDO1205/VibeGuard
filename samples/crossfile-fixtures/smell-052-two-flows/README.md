# smell-052-two-flows — the positive that pins WHICH flow is cited

Two registered handlers carry untrusted input to a sink, and they sort in the
order that makes the naive choice wrong:

    routes/a-profile.ts   req.query.name  -> res.send      [response]
    routes/b-search.ts    req.query.q     -> db.query      [query]

Severity aggregates over the flows with an existential, so the presence of the
query sink makes this `high`. A finding that then PRINTS the first flow in the
total order would print the response flow — leaving the reader with a `high`
verdict and evidence that does not justify it, which is the whole reason a flow
is carried at all.

`sanitizeOrderNote` is exported and referenced by nothing.
