# smell-052-neg-candidate-in-tests — the fixture-helper negative

`validateSignupInput` is exported, correctly named, and referenced by nothing —
and it lives in `__tests__/helpers/`. A validator written for a test suite is not
a protection missing from the request path; it is a test helper that a test
stopped calling.

The production side satisfies everything else: `POST /signup` is registered with
no guard and `req.body.email` reaches `db.query`. Candidates never come from the
test tree, which is the opposite of the rule's treatment of REFERENCES — those
are read from everywhere, including here. The two asymmetric uses of the same
path pattern are what this directory and `smell-052-neg-test-only/` pin between
them.
