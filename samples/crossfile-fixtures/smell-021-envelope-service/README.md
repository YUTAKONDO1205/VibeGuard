# smell-021-envelope-service — POSITIVE for VG-SMELL-021 (the medium band)

`src/services/envelope.ts` performs envelope encryption. It is a security
module by BEHAVIOUR — `createCipheriv` / `createDecipheriv` — and by nothing
else: its path carries no security word and neither do its exports.

That combination is the point of this fixture. Severity is `medium` because the
module computes rather than decides (nothing here says yes or no to a request),
and confidence is `medium` because only one kind of evidence is present. The
`smell-021-authz-hub` fixture is the high/high counterpart; a rule that cannot
produce both bands has a severity field that carries no information.
