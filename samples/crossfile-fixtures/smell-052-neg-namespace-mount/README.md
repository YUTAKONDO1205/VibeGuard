# smell-052-neg-namespace-mount — the namespace-object negative

`app.ts` imports `security/guards.ts` as a namespace object and mounts every
function on it. No guard is ever named, and every guard is mounted — adding one
to the module mounts it, which is the reason the module is consumed this way.

This is the same defeat as `smell-052-neg-barrel-export-star/` arriving through a
different door, and the two are separate directories because the repairs are
separate: there, the module reached the application through `export *`, which
draws no import edge at all; here it reaches it through an ordinary resolved
import whose BINDING FORM is what matters. Deleting either pattern from
`MODULE_HANDLE` leaves the other fixture green, so one directory could not have
tested both.

`GET /orders` is registered with no per-route guard and `req.query.owner` reaches
`db.query`, so the routing and taint conditions are both live.
