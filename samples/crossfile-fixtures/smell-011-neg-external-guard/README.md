# smell-011-neg-external-guard/ — the guard is not this project's

`passport.authenticate('jwt')` reduces to the middleware name `authenticate`,
which the lexicon recognises as an authentication guard — so conditions (a) and
(b) both hold and only condition (c) refuses it: nothing in this project defines
`authenticate`, so nothing here can say what it covers or whether the fourth
route was meant to be outside it.

`app.use(passport.initialize())` is here as well, and must not be read as a mount
either: its argument is a call, so there is no name to judge.

**Expected: no `VG-SMELL-011` finding.**
