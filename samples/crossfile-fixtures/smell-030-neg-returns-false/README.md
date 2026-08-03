# smell-030-neg-returns-false — NEGATIVE for VG-SMELL-030 (condition 4)

`ArchivedRecordGuard.checkPermission()` is a one-statement constant override,
exactly like the positive fixtures — except the constant is `false`.

Nothing was refused. The subclass denies everything, which is the fail-closed
direction, and the rule's accusation ("the decision disappeared") is simply not
true of it: the decision is `no`, stated once, for every subject.

`classifyOverride` must report `falsy`. It is a separate tag from `permissive`
rather than "not permissive" so that this fixture pins the direction of the
constant and not merely its presence — a rule that lost the case distinction
would still pass a test that only asserted silence.
