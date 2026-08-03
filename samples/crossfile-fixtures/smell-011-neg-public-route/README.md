# smell-011-neg-public-route/ — the unguarded write is public by design

Byte for byte the positive's shape: three mutating registrations carrying
`requireAdmin`, a fourth in the same file with an empty middleware list, the
guard defined in another file, no mounts. One condition differs — the fourth
route is `POST /password/reset`, and `reset` is in the lexicon's
`PUBLIC_BY_DESIGN_ROUTE_WORD`.

The exemption is not politeness. Password reset, login, registration, the health
probe and the payment provider's webhook are unguarded in every correct
application that has ever been written, and a rule without this condition fires
on all of them.

**Expected: no `VG-SMELL-011` finding.**
