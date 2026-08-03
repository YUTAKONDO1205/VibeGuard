# smell-013-neg-ownership

Correct code that satisfies every other condition of the rule.

`requireDocumentRole` is mounted on three routes, so the convention exists, and
`readDocument` refuses with a 403 after reading `req.user.isAdmin` — a subject
receiver and a privilege flag. It is still not a re-implementation of the guard:
the decision needs `doc`, which does not exist until the handler has loaded it,
so no route-level guard could have made it. The privilege term is the escape
hatch on an ownership rule.

`OWNERSHIP_NEIGHBOURHOOD` is what keeps the rule quiet here. Note which side of
the `isOwner` trap this fixture is on: it is excluded by the id-vs-id
COMPARISON next to the check, not by removing `isOwner`/`isAdmin` from the
shared vocabulary.
