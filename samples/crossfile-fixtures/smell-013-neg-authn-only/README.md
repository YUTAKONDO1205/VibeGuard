# smell-013-neg-authn-only

The layered architecture VG-SMELL-013 must never report, and the reason
`authz-lexicon.ts` splits `AUTHN_GUARD_WORD` from `AUTHZ_GUARD_WORD`.

`authenticateSession` is mounted on four routes. It answers WHO YOU ARE. It
does not answer WHAT YOU MAY DO, so nothing here has centralised the privilege
decision, and the inline check in `listReports` is the only place that decision
is made — which is the correct and overwhelmingly common way to write an Express
service.

The inline check IS detected (`inlineAuthorizationDecisions` returns it). The
rule is silent because condition (a) fails, and the test asserts both halves so
it cannot pass by the fixture quietly losing its check.
