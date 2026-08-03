# smell-013-scope-check

The same shape as `smell-013-bypassed-guard` with one difference that has to
move the severity: the inline decision names a scope (`billing:write`) rather
than an administrator-level privilege, so `ELEVATED` does not match and the
finding is `medium`.

Its existence is what stops the severity field from being a constant. A rule
that reports every finding at `high` under the default `--fail-on high` gate
has no severity field at all.
