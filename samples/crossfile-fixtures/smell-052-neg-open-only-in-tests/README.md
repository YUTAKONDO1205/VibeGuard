# smell-052-neg-open-only-in-tests — the probe-app negative

Every registration the SERVICE makes carries a guard. The only unguarded one is
in `__tests__/invoices.test.ts`, where the suite stands up a bare probe app to
exercise the router without authentication — which is what a test is for.

Citing that registration as the place `requireTenantAccess` should have gone
would be telling a team to add authentication to their test harness. Routing
evidence is therefore collected from the product only, while REFERENCES are still
read from the test tree; `smell-052-neg-test-only/` is the other half of that
asymmetry.

The taint flow through `listInvoices` is real and lives in the product, so
removing the test-path exclusion from the registration scan is enough on its own
to make this directory fire.
