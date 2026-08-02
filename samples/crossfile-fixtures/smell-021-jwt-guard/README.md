# smell-021-jwt-guard — POSITIVE for VG-SMELL-021 (CommonJS JavaScript)

Same smell, third syntax. `src/auth/verify-token.js` is a request guard that
verifies JWTs, written as CommonJS `require` calls in plain JavaScript, and it
reaches into eight project modules to do it.

The fixture exists because `resolveSpecifier` treats `require` differently from
`import` and because the token family is recognised through the
`jsonwebtoken` binding rather than through a method name — neither of which the
TypeScript fixtures exercise.
