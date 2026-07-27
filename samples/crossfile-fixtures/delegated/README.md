# delegated/ — falsifies condition (b)

Four route handlers spread across three controller files, all registered in
`routes.ts`, and every one of them is privileged: conditions (a)-by-file-count,
(c) ≥3 occurrences, and (d) handler code are all satisfied on the surface. What
is missing is condition **(b)**, "the checks are written directly inside each
handler, not in a middleware or guard". Each handler's first statement is a call
to the named helper `requireAdmin(req)` exported from `auth/require-admin.ts`;
the comparison against `'admin'` exists exactly once in the whole fixture, inside
that helper, which is not itself a route handler. This is the guard pattern
written as a call instead of as Express middleware — a common shape in
AI-generated Nest/Fastify/Express hybrids — and it must not fire, because the
property VG-SMELL-010 is meant to detect (the policy has no single edit site) is
not present. A rule that counted "handlers that mention authorization" rather
than "handlers that inline the comparison" fires here; that is the failure mode
this directory exists to catch.
