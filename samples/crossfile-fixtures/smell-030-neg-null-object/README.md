# smell-030-neg-null-object — NEGATIVE for VG-SMELL-030 (condition 1)

`PublicPolicy.canAccess()` returns `true` and always will. Everything the rule
looks for is present — resolved base, security-role method, trivially permissive
override, a sibling that still decides, and the family carries authorization
vocabulary (`Policy`) so the ambiguous name `canAccess` is corroborated.

It is silent for exactly one reason: the class is NAMED for the answer it gives.

That is the Null Object pattern, and it is the opposite of the smell. The smell
is a decision that vanished without anyone deciding; this is a decision made
explicit enough that every call site has to select it by type. Firing here would
be telling a team that the clearest thing they wrote is the problem.

The test asserts the override classifies as `permissive` BEFORE asserting
silence, so a fixture that drifts into a different body shape fails loudly.
