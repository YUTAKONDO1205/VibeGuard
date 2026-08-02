# smell-052-neg-monorepo — the locality negative

Two products in one repository, which is the layout the first implementation of
VG-SMELL-052 could not see.

`packages/api` is a live service: it registers `GET /invoices` with no guard and
carries `req.query.owner` into `db.query`. `packages/legacy` is a retired
package whose `validateInvoicePayload` is exported and referenced by nothing.

Every firing condition is satisfied SOMEWHERE in this repository. None of them
are satisfied in the same program. The rule stays silent because the API's app
unit — the connected component of the import graph that owns the unguarded
registration and the taint flow — occupies `packages/api/src` and
`packages/api/src/routes`, and the legacy helper is in neither.

Delete the locality check and this directory reports a package that has not been
part of the request path for as long as it has been retired.
