# smell-030-neg-unresolved-base — NEGATIVE for VG-SMELL-030 (resolution)

Two families, each with a base this package cannot read, each silent.

**1. The base is in a package.** `src/policies/vendor-*.ts` extend `PolicyBase`
from `@acme/policy-kit`. The specifier is bare, so `resolveSpecifier` leaves it
unresolved on purpose (`vendor/express.ts` matching `express` would be a
fabricated edge). Without the base's body, condition (b) has nothing to read:
there is no way to know whether `PolicyBase.canAccess` decided anything, and a
rule that assumed it did would be accusing on the strength of a name.

**2. The base is behind a barrel.** `src/policies/barrel-*.ts` extend `KitPolicy`
imported from `../kit/index.js`, which is `export * from './kit-policy.js'`. The
import RESOLVES — to `src/kit/index.ts` — and that file declares no class called
`KitPolicy`, so the lookup fails and the edge is dropped.

The second is the case worth having a fixture for. VG-SMELL-052's first
submission fired on a correctly-mounted guard reached through exactly this
construct; here the same construct makes the rule quiet instead. Re-export
following is a resolution feature this package does not have, and the failure
direction it produces here is the safe one.

The test asserts `resolvedInheritanceEdges` is EMPTY, because "no findings" is
also what a fixture with a typo produces.
