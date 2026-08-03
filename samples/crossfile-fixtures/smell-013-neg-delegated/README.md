# smell-013-neg-delegated

`req.user.hasAccess('reports:purge')` is a subject receiver, a privilege
property, and it refuses with a 403 — every condition holds except the one that
matters: the decision is DELEGATED to the subject object rather than derived in
the handler. That is the shape this rule recommends, and counting it would
accuse the codebases that did the right thing.

The exclusion is the `(` after the property, byte-identical to the test
`scattered-authorization.ts` performs. Delete the parentheses in this fixture
and the site becomes a finding, which is what makes the negative non-vacuous.
