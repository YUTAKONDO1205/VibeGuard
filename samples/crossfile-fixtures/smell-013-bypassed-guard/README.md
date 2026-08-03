# smell-013-bypassed-guard

The positive case, at `high` severity.

`requireTeamRole` is defined in `access/require-team-role.ts` and named at three
route registrations, so the project has an authorization convention. The fourth
endpoint — `/summary` — is registered without it, and `teamSummary` re-derives
the same admin decision in its own body and refuses the request itself.

Exactly ONE inline site, so VG-SMELL-010 is silent (it needs three across two
files) and the two rules do not both speak about this line.
