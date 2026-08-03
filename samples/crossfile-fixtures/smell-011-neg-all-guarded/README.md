# smell-011-neg-all-guarded/ — every write carries the guard

Condition (b) fails: there is no unguarded MUTATING registration. The one
unguarded registration is a `get`, and it is here on purpose rather than as
filler — the rule compares like with like, and plenty of correct services guard
every write while leaving reads open.

If `get` ever started counting, this directory would be the first thing to go
red, and it would go red on a service that has done nothing wrong.

**Expected: no `VG-SMELL-011` finding.**
