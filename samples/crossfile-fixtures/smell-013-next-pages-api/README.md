# smell-013-next-pages-api — the shape VG-SMELL-013 could not see

**This directory is a POSITIVE. It must produce exactly one `VG-SMELL-013`
finding, on `pages/api/reports.ts`.**

## Why it exists

`packages/analysis-graph/src/design-smells-crossfile/index.ts` records that
VG-SMELL-013 reached its decision point **0 times in 1,000 real repositories**,
and that the cause was structural rather than a threshold:

> Next.js `pages/api` handlers write no route registration at all, so premise
> (a) cannot form, and their `const handler = withX(..., async (req,res) => {…})`
> arrows are not indexed as symbols, so premise (b) cannot form either.
> LAION-AI/Open-Assistant has exactly the shape this rule describes (a
> `withAnyRole` convention across 11 endpoints, one of which re-derives the role
> inline and returns 403) and the rule cannot see it. 013 is not rare here — it
> is unreachable here. A future wave should read that as "extend the
> route/handler model", not "add fixtures".

This fixture is that shape, reduced to its smallest form. It exists to prove the
route/handler model was extended, and it fails the day either half is reverted:

| half | what it supplies | which file proves it |
| --- | --- | --- |
| file-path routes | `pages/api/**` is a route with the wrapper in the middleware position | the three guarded endpoints |
| wrapped-binding symbols | `const handler = withX(async (req,res) => {…})` has a body a rule can read | `pages/api/reports.ts` |

Neither half alone produces the finding. Without the first, no guard is ever
mounted and premise (a) is empty; without the second, the offending handler has
no indexed body and premise (b) is empty.

## The layout

| file | role |
| --- | --- |
| `lib/authz.ts` | `withAnyRole` — the authorization convention |
| `lib/session.ts` | `withSession` — AUTHENTICATION only, and deliberately so |
| `pages/api/teams.ts`, `members.ts`, `invites.ts` | three endpoints that delegate to `withAnyRole` — premise (a), which needs three |
| `pages/api/reports.ts` | **the offender**: wrapped only by `withSession`, and re-derives the role inline and returns 403 |
| `pages/index.tsx` | false-positive control — a page, not an endpoint |
| `pages/dashboard/settings.tsx` | false-positive control — a NESTED page, which is the one a loosened `pages/**` predicate would match |
| `lib/api.ts` | false-positive control — the word `api` in a file name is not a route |

## The negative that is doing the most work

`withSession` is on the offending endpoint. It is a wrapper, in the same
position, on the same kind of file — and it establishes nothing, because
`isAuthzGuardName('withSession')` is false. That is the split
`authz-lexicon.ts` exists for: layered authentication plus a per-handler
privilege decision is the DEFAULT correct architecture, and a rule that read
`withSession` as a guard would fire on most correct Next.js projects.

Rename `withAnyRole` to `withSession` in the three guarded endpoints and this
directory must go silent. That is the sharpest single check on the fixture.
