# smell-041-generic-words — VG-SMELL-041 NEGATIVE

Four calls that carry a vocabulary word and are not security operations:
`ensureParentDirectory`, `stripTrailingWhitespace`, `quoteForDisplay`, and
`escapeRegExp`.

Expected: **no `VG-SMELL-041`**, with **taint flows present** (two: the file
write and the response).

Falsifies two separate mechanisms:

- the narrowed `TRANSFORMER_WORDS` / `VALIDATOR_WORDS` — restoring `ensure`,
  `strip` or `quote` to either set turns this directory red;
- `NOT_A_GUARD` — `escapeRegExp` carries a word the vocabulary DOES admit and is
  excluded by name, because escaping a value for a pattern says nothing about
  whether it is safe for a shell, a statement, or a page.

`escapeRegExp` is deliberately written as its own statement rather than nested
inside `new RegExp(...)`: nested, `CALL_RE` never collects it (see the rule's
last KNOWN GAP) and the directory would be silent for a reason that has nothing
to do with `NOT_A_GUARD`.

## ★ Why the calls sit AFTER the sink

A validator word placed BEFORE a sink suppresses the finding, so a fixture
written that way is silent under both the old and the new vocabulary and pins
nothing. Placed after it, each call is an INVERTED finding for exactly as long as
its word is admitted — which is what makes the directory a falsification rather
than an illustration.

## ★ What the measurement was

`quote` matched `quotePs` in `decolua__9router` and produced two of the rule's
three findings across 1,000 real repositories. `ensure` matched
`ensureParentDirectory`. Both words name what a function does to a string, and
only sometimes why; the rule's word sets are now short enough that a false
positive is removed by deleting one entry rather than by weakening a heuristic
everything else stands on.
