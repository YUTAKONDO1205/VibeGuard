# smell-052-neg-mounted/ — the validator is applied at the route

One condition away from `smell-052-unwired-validator/`, and the condition is the
whole rule: `validateInput` is passed to `app.post('/comments', validateInput,
createComment)`. Everything else that makes the positive fire is still here — an
exported security-named validator, live routes, and `req.body.text` reaching
`db.query` — so if this directory ever produces a finding, the rule has stopped
looking at whether the symbol is wired and started reporting on its existence.

`app.get('/comments', listComments)` is registered **without** a guard on
purpose. Without it, this fixture would be silent for two independent reasons
(the symbol is referenced, *and* no unguarded registration exists), and a
negative that fails two conditions at once cannot tell you which one broke.

**Expected: no `VG-SMELL-052` finding.**
