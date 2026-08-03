# smell-011-unguarded-admin-route/ — the positive

`requireAdmin` is applied at four mutating registrations across two files, three
of them in `routes/admin-routes.ts`. The fourth write in that file —
`POST /users/:id/promote` — is registered with an empty middleware list.

Everything the rule needs is here and nothing else is:

- **(a)** four guarded mutating registrations, above the three-site threshold;
- **(b)** one further mutating registration in the same file with no guard at all;
- **(c)** `requireAdmin` is defined in `middleware/require-admin.ts`, not in the
  file that registers the unguarded route;
- no `app.use(<guard>)` anywhere — the two `app.use` calls mount routers with no
  guard in front of them, which is the shape the rule must *not* read as a mount.

**Expected: one `VG-SMELL-011` finding**, `high` (the file names an
administrator surface) and `medium` confidence (the convention spans two files).
