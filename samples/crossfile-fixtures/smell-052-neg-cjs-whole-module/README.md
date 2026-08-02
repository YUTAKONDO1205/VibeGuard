# smell-052-neg-cjs-whole-module — the `require()` negative

`server.js` mounts the guard with `app.use(require('./security/require-bearer-auth'))`.
That protects every route registered after it, and it never writes the word
`requireBearerAuth` anywhere. A reference scan made of identifiers cannot see it,
which is how the first implementation of VG-SMELL-052 reported a mounted guard
as unmounted.

The import graph knew. `require('./security/require-bearer-auth')` produces a
resolved `ImportEdge` exactly like any other CommonJS import; the rule simply
never looked at it. `MODULE_HANDLE` is the repair, and it distinguishes this from
`const { renderReport } = require('./handlers/report')` — a destructured binding
DOES name what it takes, so the lexical scan can see that one.
