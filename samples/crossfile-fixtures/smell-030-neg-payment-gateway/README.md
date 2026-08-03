# smell-030-neg-payment-gateway — NEGATIVE for VG-SMELL-030 (the `authorize` collision)

`OfflineGateway.authorize()` returns `true`. `PaymentGateway.authorize()`
decides. `StripeGateway.authorize()` decides differently. Every structural
condition the rule has is satisfied — resolved base, closed-list method name,
one-statement permissive override, a sibling that still decides.

It is silent because `authorize` here is the CARD-AUTHORIZATION sense: reserving
funds against a card. An "offline" gateway that approves everything is a normal
thing to write for a terminal that has lost its network link, and telling a
payments team that their store-and-forward path is an access-control bypass is
the kind of finding that makes people turn a linter off.

Nothing in the subclass separates the two senses. The FAMILY does:
`PaymentGateway`, `src/payments/gateway.ts`, `OfflineGateway` and
`src/payments/offline-gateway.ts` tokenise to no word in either
`AUTHZ_GUARD_WORD` or `AUTHN_GUARD_WORD`, so the ambiguous name is not read as
access control at all.

Honest about the evidence: unlike the `isAllowed` collisions (a rate limiter and
a circuit breaker, both found in `paper_data/corpus1k`), this one is ARGUED
rather than measured — the corpus contains no payment-gateway family. The
mechanism that silences it is the same one, and the fixture exists so the claim
is at least falsifiable.
