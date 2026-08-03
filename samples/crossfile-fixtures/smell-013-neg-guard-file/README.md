# smell-013-neg-guard-file

Condition (c): the guard has to be defined in a DIFFERENT file from the handler.

`gating/tier-checks.ts` holds both the mounted guard and a route handler
(`tierStatus`) that decides privilege inline and refuses. The path carries no
word from `AUTHORIZATION_HOME_WORD`, so the placement exclusion does not apply
and the finding is suppressed by condition (c) alone. That is also why the file
is named `tier-checks.ts` and not `require-tier-policy.ts`: `policy` is a word
in both `AUTHORIZATION_HOME_WORD` and the symbol table's `SECURITY_PATH_WORDS`,
and either of them would have excluded the site before condition (c) could —
leaving a fixture that passed while testing nothing.

The test asserts that `inlineAuthorizationDecisions` DOES return the site — the
per-site half of the rule found it — and that the rule still emits nothing. A
negative that could not distinguish "excluded by (c)" from "never detected"
would pass just as well if the detector stopped working.
