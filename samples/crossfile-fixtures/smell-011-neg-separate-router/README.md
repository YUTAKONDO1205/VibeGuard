# smell-011-neg-separate-router/ — the omission is in a file that never guards

The default layout of an Express service: an admin router where every write
carries `requireAdmin`, and a public router where one does not.

Conditions (a), (b) and (c) all hold — a three-site convention, an unguarded
mutating registration, the guard defined elsewhere — and there is nothing wrong
with this code. A rule that fires here is saying "not every route in your project
is an admin route", which is true of every project.

The condition that refuses it is that the accused file must apply the guard to
its own other writes. Without it this rule fires on a large fraction of correct
applications, which is the shape both rules rejected at the corpus gate had.

**Expected: no `VG-SMELL-011` finding.**
