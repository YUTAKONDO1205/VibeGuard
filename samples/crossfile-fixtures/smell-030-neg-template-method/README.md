# smell-030-neg-template-method — NEGATIVE for VG-SMELL-030 (condition 6)

`AbstractAuthorizer.authorize()` throws `new Error('subclasses must implement
authorize()')`. That is the Template Method pattern with a hand-written abstract
method, and it changes what every subclass IS: they are IMPLEMENTING, not
refusing. `ExportAuthorizer` returning `true` is a first implementation that
happens to be permissive; there was never an inherited decision to remove.

The corpus agrees this is the common shape rather than a corner case. The only
`return true` override of a security-named method in all 1000 repositories of
`paper_data/corpus1k` —
`ashishps1__awesome-low-level-design/.../execution_strategy.py:26` — has exactly
this base, spelled `@abstractmethod def can_execute(...): pass`.

Everything else about this fixture is a firing configuration: the base resolves,
`ExportAuthorizer.authorize` classifies as `permissive`, `TenantAuthorizer`
supplies differential evidence, and the directory `src/authorization/` supplies
the family corroboration that the ambiguous name `authorize` needs. The single
difference from a positive is the base's body, which is what the test asserts.

A TypeScript `abstract authorize(): boolean;` never reaches this branch at all —
it has no body, so the indexer records no method and the family is silent one
step earlier.
