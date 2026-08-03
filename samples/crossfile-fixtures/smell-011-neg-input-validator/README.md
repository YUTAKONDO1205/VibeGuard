# smell-011-neg-input-validator/ — the convention is not an auth convention

Structurally identical to the positive: three mutating registrations sharing one
middleware defined in another file, and a fourth with an empty middleware list.
The middleware is `validateOrderBody`.

The lexicon's guard vocabulary declines the name, and that refusal is the only
thing standing between this rule and a finding that accuses a project of missing
an authorization boundary it never claimed to have. Every service has a
consistently applied middleware; most of them are not guards.

**Expected: no `VG-SMELL-011` finding.**
