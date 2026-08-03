# smell-011-neg-barrel-mount/ — the parent mount is reached through a barrel

`smell-011-neg-parent-mount/` with one indirection added: `app.ts` imports
`billingRouter` from `./routes/admin`, which is an `index.ts` whose entire
content is `export * from './billing-routes'`.

`export *` produces **no** `ImportEdge`, so following `graph.importsOf` from the
mount target reaches nothing and `routes/admin/billing-routes.ts` looks
unprotected. Firing here is a known, already-made mistake — VG-SMELL-052 shipped
it and had to be reworked — and this directory is where it would come back.

**Expected: no `VG-SMELL-011` finding.**
