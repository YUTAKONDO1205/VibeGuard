# smell-030-admin-controller — POSITIVE for VG-SMELL-030

The canonical shape, in TypeScript.

`BaseController.authorize()` reads a required permission off the subject. Two
controllers extend it. `ReportController` overrides `authorize()` with its own
decision; `AdminController` overrides it with `return true` and nothing else.

Everything the rule needs is here and each piece is separable:

| condition | supplied by |
| --- | --- |
| (a) the base resolves in-project | `import { BaseController } from './base-controller.js'` |
| (b) the base declares a security-role method | `authorize` |
| (c) the override is trivially permissive | `AdminController.authorize` |
| (d) differential evidence | `ReportController.authorize` still decides |
| family corroboration | `authorize` is ambiguous; the word `admin` in `AdminController` supplies it |
| severity `high` | `admin` is an ELEVATED path word |

Removing any single one of those must silence the fixture, which is what the
test file asserts one condition at a time.
