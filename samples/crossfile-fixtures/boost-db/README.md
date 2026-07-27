# boost-db — VG-SMELL-010 POSITIVE, boosted to `high` by data mutation alone

The `boost-none/` fixture with one variable changed: each of the three handlers
writes to a data store. Same `catalog/` directory (so no security path word,
no `routes`/`controllers`/`middleware` layer), same `role !== 'editor'` check
(so no privilege word). The only thing that can move the severity is the
mutation, which is what makes this fixture a test of that condition rather than
a test of "some boost fired".

Two mutation shapes on purpose, because they are found by two different
mechanisms:

| file | shape | how it is found |
| --- | --- | --- |
| `catalog/listings.ts` | `listingCollection.updateOne(…)`, `.deleteOne(…)` | a closed set of method names, matched in the BLANKED handler body |
| `catalog/pricing.ts` | `pool.query('update price_book set … where …', […])` | a SQL verb pair, matched in the ORIGINAL text and then required to sit where the blanked copy has whitespace — i.e. inside a string literal |

The second row is the interesting one. Blanking erases string CONTENTS, so a SQL
statement is invisible in the body the method-name scan reads; a boost that only
looked at the blanked body would report "no mutation" for the single most common
way a handler writes to a database. Reading the original text instead brings a
new problem — a commented-out statement would count — so the position is checked
against the blanked copy and against the comment structure before it is
believed.

The statement is parameterised (`$1`, `$2`) deliberately. This fixture's subject
is *that the handler writes*, not *that the handler is injectable*, and a
concatenated statement would drag the single-file SQL rules into a corpus that
is supposed to isolate one variable.

`create` / `save` / `remove` are **not** in the method set and must not be added:
`res.save`, `cache.remove`, and `createServer` are ordinary, and a set wide
enough to catch an ORM's `save()` catches all of them too.

Expected: exactly one `VG-SMELL-010` finding, `severity: high`,
`confidence: medium` (3 sites over 2 files, below the 5×3 confidence bar — the
boost moves severity and must leave confidence alone).

## The measurement that argues against this fixture's condition

Recorded here because a fixture that only ever confirms is not worth much.

Over `paper_data/corpus1k_vibe` (1,683 repositories, measured 2026-07-28), the
mutation condition holds for 63 of 108 check sites — 58%, which is a real
partition. But a finding aggregates its sites with ∃ and has at least three of
them, so 58% per site becomes ≥93% per finding, and the corpus bears that out:
**all 9** projects with any site have a mutating handler, and of the 5 that clear
the thresholds and actually emit a finding, the severity split moves from
2 high / 3 medium to **5 high / 0 medium**.

That is the same failure `routes`/`controllers` was rejected for (95.4% of
sites), one stage weaker. It ships anyway because the evidence against it is
n = 5 findings while the evidence against the routing layer is n = 108 sites —
see the severity comment in `scattered-authorization.ts` for the full argument
and for the trigger that should reopen it.

`boost-none/` is the fixture that stays `medium` under either resolution.
