# smell-052-neg-barrel-export-star — the re-export negative

`security/index.ts` is a barrel: `export * from './require-admin-role'`. `app.ts`
imports it as a namespace and mounts everything on it. Every guard in that
directory is therefore mounted BY CONSTRUCTION — adding a file to `security/`
mounts a guard, which is the entire reason the barrel is written that way.

Nothing anywhere spells `requireAdminRole`, so a reference scan that reads only
identifiers concludes it is unwired, and the first implementation of
VG-SMELL-052 reported it at `high` for that reason. `export *` also produces no
import edge — the indexer's `JS_IMPORT` needs the `import` keyword — so the
`fanIn`-based confidence band read 0 and did not lower it either.

`GET /reports` really is registered with no per-route guard and the handler
really does carry `req.query.owner` into `db.query`, so the routing and taint
conditions are both live. The silence comes from `MODULE_HANDLE`.
