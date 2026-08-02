# smell-052-neg-flow-only-in-tests — the fixture-data negative

The service reads nothing a client controls: `GET /status` answers from a
constant. The only untrusted-input-to-sink flow in the tree is in
`__tests__/status.test.ts`, where the suite builds a probe endpoint that echoes
its own query string in order to assert the echo.

Taint inside a test is a statement about the test. Treating it as the evidence
that a service handles attacker-controlled data would make every repository with
an integration suite look like it does, which is the shape that gets a rule
switched off.

`GET /status` really is registered with no guard, and `escapeCommentHtml` really
is exported and referenced by nothing, so this directory is one condition away
from firing and that condition is the one being isolated.
