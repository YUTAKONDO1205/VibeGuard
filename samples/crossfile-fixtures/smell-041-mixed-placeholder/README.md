# smell-041-mixed-placeholder — VG-SMELL-041 POSITIVE ×2 (INVERTED)

**The directory that keeps `sinkIsParameterized` from becoming a blanket
excuse.** `smell-041-parameterized/` proves the test silences correct code; a
condition that only ever silences can be widened without any test noticing, so
this one proves it still speaks.

Expected: exactly **two** `VG-SMELL-041`, both INVERTED, both `high` severity
(`query` and `exec` sinks) and `high` confidence (one hop each).

| function | why it LOOKS parameterised | which sub-check refuses it |
| --- | --- | --- |
| `searchOrders` | the statement really does contain `state = ?` | no chain name may appear in the first argument — `'%${term}%'` does |
| `runReport` | the first argument contains `?` | a placeholder must have been INSIDE a string literal; this one is a `??` operator |

Falsifies the two internal conditions of `sinkIsParameterized`. Dropping either
turns the corresponding function silent while the other stays green, which is
why one function cannot stand in for the other.

## ★ How "inside a string literal" is decided without lexing

Blanking is length-preserving, so a character that is `?` in
`SourceFile.content` and a space in `StructureIndex.blanked` was inside a
literal. That single comparison separates `'WHERE state = ?'` from `bin ??
DEFAULT_BIN`, and neither text can do it alone.
