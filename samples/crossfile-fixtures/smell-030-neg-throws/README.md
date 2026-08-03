# smell-030-neg-throws — NEGATIVE for VG-SMELL-030 (condition 3)

`TenantScopedGuard.isAuthorized()` ends with `return true`, and is fail-closed.

The statement above the return raises `ForbiddenError` when the subject's tenant
does not match. A subclass that can throw has not removed the decision; it has
moved the "no" from a return value to an exception, which is if anything the
harder failure to ignore at the call site.

This is the negative most likely to be misread by a rule that looks only at the
last statement of a body, which is why the fixture ends in the exact token the
rule fires on. `classifyOverride` must report `throws`.

`isAuthorized` is a self-evident name, so corroboration is not the cause of the
silence.
