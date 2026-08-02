# smell-052-neg-imported-service/ — used, but nowhere near a route

`verifyToken` is exported from `security/verify-token.ts` and is used exactly
once, by `services/socket-gateway.ts`, on a WebSocket upgrade. There is no
`app.get('/x', verifyToken, …)` anywhere, no `app.use(verifyToken)`, and the HTTP
routes in `app.ts` are registered with no guard argument at all — so every
observation the rule makes about the ROUTING layer is identical to the positive.

The symbol is nonetheless wired: something in this project calls it. A rule that
asks "does this name appear in a route's middleware list" answers no here and
fires; a rule that asks "is this name referenced anywhere in the project" answers
yes and stays quiet. The second question is the one VG-SMELL-052 asks, and this
directory is why.

The WebSocket path is not an accident either. Guards that live outside Express's
middleware chain — socket upgrades, GraphQL resolvers, queue consumers — are the
most common legitimate reason a security helper is real and route-invisible, and
they are the population a route-shaped rule would misfire on hardest.

**Expected: no `VG-SMELL-052` finding.**
