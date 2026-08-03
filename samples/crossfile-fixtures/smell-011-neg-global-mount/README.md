# smell-011-neg-global-mount/ — a guard is mounted for the whole application

`app.use(requireLogin)` with no path and no router after it. This is the single
most common correct architecture in Express: authentication mounted once,
authorization decided per route where the resource is known.

The rule goes silent for the **whole project**, not just for this file. Mount
order is execution order, a lexical reading of source cannot see it, and a rule
that guessed would be guessing about the one thing that decides whether the
unguarded registration below is reachable anonymously.

**Expected: no `VG-SMELL-011` finding.** Deleting the `app.use(requireLogin)`
line turns this directory into a positive, which is what makes it a test of that
line rather than of anything else.
