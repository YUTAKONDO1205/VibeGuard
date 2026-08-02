# smell-052-neg-not-a-route — the `.get(` that is not an endpoint negative

The indexer's route pattern is every `.get(` in the language, so three things in
`app.ts` parse as registrations and none of them is one:

    config.get('database.url', DEFAULT_DATABASE_URL)   a settings key, not a path
    store.get(reportCacheKey)                          no literal first argument
    app.get('/incidents', handlers['listIncidents'])   no handler identifier

Each is excluded by a different condition, and each condition has to survive on
its own: "an unguarded registration exists" is a PERMISSIVE condition here, so a
spurious one makes the rule more willing to fire AND gets printed in the finding
as the place the sanitizer should have gone.

`GET /search` is registered WITH a guard, so the taint flow through
`searchIncidents` is present and attributable while the open-slot count stays at
zero. `sanitizeIncidentTitle` is exported and referenced by nothing.
