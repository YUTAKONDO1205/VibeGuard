# smell-013-neg-authz-home

`AUTHORIZATION_HOME_WORD`: a handler that happens to live under
`middleware/` is in the part of the tree where authorization is supposed to be
written, and a rule that recommends centralising authorization must not report
the centre.

Unlike `smell-013-neg-guard-file`, the exclusion happens inside
`inlineAuthorizationDecisions`, so the test asserts zero decisions AND an
established guard — the premise held and the site was refused on placement.
