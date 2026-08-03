# smell-011-neg-parent-mount/ — the router is mounted behind a guard

`app.use('/admin', requireAdmin, invoiceRouter)`. The guard is not the last
argument, so unlike `smell-011-neg-global-mount/` its reach *is* knowable: it is
whatever `invoiceRouter` can reach, and the import graph says what that is.

So this fixture does not silence the rule globally — it protects one subtree.
`routes/invoice-routes.ts` still shows a three-site `requireOwner` convention and
a fourth write with an empty middleware list, and the finding must not be made
anyway, because that file sits behind the parent mount.

**Expected: no `VG-SMELL-011` finding.**
