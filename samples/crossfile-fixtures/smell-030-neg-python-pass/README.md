# smell-030-neg-python-pass — NEGATIVE for VG-SMELL-030 (condition 5)

`LegacyGuard.check_permission` is `pass`. **This reads backwards and it is the
most important negative in the set.**

`pass` looks like the most complete refusal available — the body is literally
nothing. It is the opposite. A Python function that falls off the end returns
`None`, `None` is falsy, and every caller writing `if guard.check_permission(a):`
therefore DENIES. The subclass made the check fail CLOSED.

It is very possibly a different bug — a stub nobody finished. That is a
different finding with a different fix, and merging the two would make the
message wrong for whichever one the reader has in front of them.

`classifyOverride` must report `empty`, and `empty` is deliberately absent from
`DIFFERENTIAL_SHAPE` as well: a stub is not evidence that the siblings decide.

The TypeScript analogue is `checkPermission() {}`, which returns `undefined` and
classifies identically.
