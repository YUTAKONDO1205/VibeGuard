# smell-052-neg-all-routes-guarded/ — there is no empty slot to point at

`sanitizeReportTitle` is exported, security-named, and referenced by nothing.
`req.body.title` reaches `db.query` inside a registered handler, so untrusted
input is live. The difference from the positive is that **every** route in this
project already mounts `requireAdmin`, so there is no registration anywhere at
which a guard was omitted.

That matters because of what the finding actually says. VG-SMELL-052 does not
report "this function is unused" — it reports "the protection you generated was
never connected", and it cites the registrations where it would have gone. With
every registration already carrying a guard, the rule has no such location to
cite, and a finding whose evidence section would be empty is a finding making a
claim it cannot support. The far likelier reading of this codebase is that
`sanitizeReportTitle` is a leftover from a refactor, which is a maintainability
observation and not this rule's business.

Three `app.use` calls are here, and each one is a different way for a rule to be
wrong about what a registration is:

| line | why it is not an unguarded endpoint |
| --- | --- |
| `app.use(express.json())` | the argument is a call, so there is no handler name at all |
| `app.use(requireAdmin)` | the handler slot holds a named function and the middleware list is empty — read as a route it is indistinguishable from an unguarded endpoint |
| `app.use('/reports', requireAdmin)` | it even has a path literal starting with `/`, so the "does the first argument look like a route path" test passes and only the method tells you it is a mount |

The third is the sharp one. A `use` mount is not an endpoint — its "handler" IS
the guard — and the only thing separating it from `app.get('/reports', handler)`
is the verb.

`routes/reports.ts` carries a fourth trap that is not an `app.use` at all:
`summaryCache.get(cacheKey)`, an ordinary `Map` read. The indexer's route
pattern is every `.get(` in the language, so this is recorded as a registration
whose first argument is `cacheKey` and whose "handler" is `cacheKey` — an
endpoint with no guard, as far as the shape goes. What disqualifies it is that
its first argument is not a path literal. Without that test this directory
reports one open registration and fires.

**Expected: no `VG-SMELL-052` finding.**
