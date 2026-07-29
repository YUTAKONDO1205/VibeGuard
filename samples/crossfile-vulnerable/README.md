# samples/crossfile-vulnerable — VG-SMELL-010 positive corpus

## What must fire

Exactly **one** `VG-SMELL-010` (Scattered Authorization) finding, at **high** severity.

This directory is the positive half of the VG-SMELL-010 gate. It is a small
Express service in TypeScript, written the way a coding assistant writes one when
it is asked for the endpoints one at a time: every handler is individually
correct, imports resolve, the routes work — and the authorization policy exists
nowhere except duplicated inside four handler bodies.

## Why it fires, condition by condition (design addendum §7.2)

The rule fires when **all four** conditions hold. Each is satisfied here:

**(a) similar role/admin/permission checks exist in multiple files.**
Three controller files each decide privilege from the request's user object:

| file | line shape |
| --- | --- |
| `controllers/user-controller.ts` | `if (req.user.role !== 'admin')` |
| `controllers/user-controller.ts` | `if (!currentUser.isAdmin)` |
| `controllers/billing-controller.ts` | `if (user.role !== 'owner')` |
| `controllers/report-controller.ts` | `if (actor.role !== 'admin' && actor.role !== 'superuser')` |

Note that the four are only *similar*, never identical: three different receiver
names (`req.user`, `currentUser`, `actor`), two different accessors (`.role`
string compare and the `.isAdmin` boolean), and three different failure modes
(`403 json`, `throw`, `403 empty`). That variation is the point — it is what
makes the duplication invisible to a reader and to a grep, and it is why the
smell is worth detecting structurally rather than by exact-text duplication.

**(b) the checks are written directly inside each handler, not in a middleware
or guard.** `app.ts` mounts exactly three routers and no authorization
middleware. Every registration in `routes/` is the two-argument form
`router.<verb>(path, handler)` — there is no name in the guard position that a
reader could follow to find the policy.

**(c) three or more occurrences in the same project.** Four sites, one over the
threshold, so the fixture also demonstrates that the rule is not merely counting
to exactly three.

**(d) concentrated in API route / controller / handler code.** All four sites are
in files under `controllers/`, each of which is the terminal handler argument of
a route registered in `routes/`. Nothing outside the request path compares a
role here; the data layer in `data/store.ts` is deliberately inert.

## Severity

**high**, not medium. §7.2 escalates when admin/owner/superuser privilege is
involved, and all three of those words appear across the four sites.

## Deliberate non-properties

- **No `vibeguard:disable` pragma anywhere.** The gate would be meaningless if
  the corpus could be silenced.
- **No single file holds three sites**, so `VG-SMELL-012` (Primitive Role Check,
  which needs ≥3 comparisons *within one file*) must stay silent. If a scan of
  this directory reports VG-SMELL-012, either that rule's per-file threshold
  regressed or a file here grew a third comparison — check the file counts before
  suspecting VG-SMELL-010.
- **No ordinary vulnerability.** No secrets, no `eval`, no string-concatenated
  SQL, no disabled TLS. A finding from any non-design rule on this directory is a
  bug in that rule or an accident in this corpus, not a feature of the fixture.
  (The count was 47 when this was written and is 71 today; the property is "none
  of them fires here", which does not depend on the number.)

## Negative counterparts

`samples/crossfile-safe/` is the same service refactored behind one middleware
and must produce zero findings. `samples/crossfile-fixtures/` isolates each of
the four conditions above, one per subdirectory.
