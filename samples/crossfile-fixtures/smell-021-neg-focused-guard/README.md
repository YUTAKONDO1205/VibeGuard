# smell-021-neg-focused-guard — NEGATIVE for VG-SMELL-021

`src/security/require-role.ts` is unambiguously a security module: it makes
three authorization decisions and nothing else. It depends on two modules.

This is the design the rule is asking people to have, and it is the fixture that
would be most damaging to fire on. The test asserts the membership premise
first — `securityOperations` really does find the decisions — so the silence is
attributable to the fan-out conditions and not to the rule failing to recognise
a guard at all.
