# smell-011-neg-two-guarded/ — two guarded writes is not a convention

Two registrations carry `requireAdmin`, one does not. Two is a coincidence: a
create and an update guarded the same way is what one commit produces, not a
decision the project has made, and `MIN_CONVENTION_ROUTES` is 3 for the same
reason and with the same argument as `MIN_SITES` in `scattered-authorization.ts`.

**Expected: no `VG-SMELL-011` finding.** Adding a third guarded write turns this
directory into a positive.
