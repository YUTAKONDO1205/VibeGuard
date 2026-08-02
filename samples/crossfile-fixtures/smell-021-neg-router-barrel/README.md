# smell-021-neg-router-barrel — NEGATIVE for VG-SMELL-021

`src/routes/index.ts` imports eight route modules and mounts them. Its fan-out
is the highest in the project and clears every fan-out condition the rule has:
the absolute floor, the project-share floor (8 of 24 modules) and the
project-tail floor.

It must stay silent, because it decides nothing. An aggregator's dependencies
are its CONTENTS, not things its behaviour rests on, and the initialisation-order
and attack-surface arguments this rule makes do not apply to a file that only
forwards. The test asserts the fan-out premise first, so the silence is earned
rather than accidental.

It deliberately declares a function (`mountRoutes`) so the silence comes from
the membership test alone and not from "the file declares nothing".
