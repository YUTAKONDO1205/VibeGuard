# boost-none — VG-SMELL-010 POSITIVE at `medium` (the boost sentinel)

Three inline `role !== 'editor'` checks across two files, registered as three
route handlers with no guard argument. The rule **must** fire here.

**The point of this fixture is the SEVERITY, not the finding.** It is the only
directory in the corpus where `VG-SMELL-010` is expected at `medium`, and it
exists to fail the day every finding becomes `high`.

Why that failure is the one worth guarding against: `#22d` adds three more
Security Context Boost conditions on top of the privilege-word one, and each of
them is a property of ordinary web code rather than of dangerous web code. A
boost vocabulary drawn one word too wide — `user` in a path, `controllers/` as a
directory — turns every finding this rule emits into `high`, at which point the
severity field carries no information and the default `--fail-on high` gate
stops distinguishing anything. A regression like that is invisible in a corpus
where every fixture is `high` already, which is what the corpus looked like
before this directory existed.

So every boost condition is deliberately absent:

| condition | why it is false here |
| --- | --- |
| privilege word in the check | compares against `editor`, never `admin` / `owner` / `superuser` |
| security word in the path | `catalog/listings.ts`, `catalog/pricing.ts` — no `auth` / `security` / `token` / `permission` / `admin` / `user` token |
| route / controller / middleware directory | handlers live under `catalog/`; registration is in `app.ts` at the root |
| data mutation in the handler | `.slice()`, `.find()` — reads only, and no SQL string anywhere |

Expected: exactly one `VG-SMELL-010` finding, `severity: medium`,
`confidence: medium` (3 sites over 2 files is below the 5×3 confidence bar).

If you are editing this directory, the checks are load-bearing in a way the
other fixtures' are not: changing `editor` to `admin`, moving the files under
`controllers/`, or adding an `.updateOne(` call anywhere in a handler body all
flip the expected severity, and the test that pins it will tell you so.
