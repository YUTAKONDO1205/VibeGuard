# boost-authpath — VG-SMELL-010 POSITIVE, boosted to `high` by the file path alone

The `boost-none/` fixture with one variable changed: the handlers live under
`auth/`. Same `role !== 'editor'` check (no privilege word), no `routes`/
`controllers`/`middleware` directory, and nothing in any handler writes. The only
thing that can move the severity is the path word.

## Why the handlers are written inline, when every other fixture exports them

This is the part worth reading before editing anything here.

`symbol-table-builder` judges an **exported** symbol in a file whose path carries
a security word — `auth`, `middleware`, `guard`, `policy`, … — to be a **guard**,
and VG-SMELL-010 excludes guards from its population before any boost is
considered. That rule is right and load-bearing: it is a large part of why
`samples/crossfile-safe` stays silent.

It also collides head-on with this fixture's subject. Written in the shape the
rest of the corpus uses —

```ts
// auth/sessions.ts
export function listSessions(req, res) { … }   // ← judged a GUARD, by placement
```

— all three handlers are guards, the rule sees no population at all, and the
directory produces **zero** sites no matter what the boost does. That is not a
hypothesis: `scattered-authorization.test.ts` builds exactly that project in a
scratch directory and asserts the zero, so the claim is checked rather than
remembered.

Registering the handlers inline at the router sidesteps it, because an inline
handler is an anonymous symbol that is not exported:

```ts
sessionRouter.get('/', (req, res) => { … });    // ← a handler, not a guard
```

The consequence, stated plainly so nobody has to rediscover it: **the `auth`
half of the boost's path vocabulary is only reachable for inline handlers.** For
the named-export shape it is dead, and the conditions that do the work there are
`security`, `token`, `permission`, `admin`, and `user`, none of which the symbol
table treats as guard placement. The entries stay in the vocabulary anyway —
inline registration is extremely common in the code this project targets, and
keeping them costs nothing.

Expected: exactly one `VG-SMELL-010` finding, `severity: high`,
`confidence: medium` (3 sites over 2 files, below the 5×3 confidence bar).
