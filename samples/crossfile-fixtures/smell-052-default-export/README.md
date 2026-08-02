# smell-052-default-export — the positive the first implementation could not see

`validateSearchQuery` is written the way a generator most often writes a single
-purpose module: `export default function validateSearchQuery(...)`. It is
exported, correct, and mounted nowhere.

The first implementation of VG-SMELL-052 could not report it, and the reason took
three separate misses stacked on each other: `IndexedSymbol.exported` is false
because the indexer looks for `export` immediately before `function` and
`default` is in the way, `StructureIndex.exportedNames` records the literal
string `default`, and the rule's own export-surface span stopped at the keyword
`function` instead of reaching the name. The symbol was not even a candidate.

Nothing imports `validators/validate-search-query.ts`, so no module handle exists
that could reach the default binding either, and the finding is `medium`
confidence rather than `low`.
