# smell-021-neg-small-project — NEGATIVE for VG-SMELL-021

`src/auth/authorize.ts` is a security module and depends on eight others, which
clears the absolute fan-out floor exactly. The project has twelve analysable
modules, so those eight are two thirds of everything there is.

"Responsibility is concentrated here" is not a finding about a program with
nowhere else to put it. The rule stays silent because
`fanOut * MAX_PROJECT_SHARE_DENOMINATOR > modules`, and the test asserts the
fan-out and the module count so the fixture cannot drift over the boundary
without saying so.
