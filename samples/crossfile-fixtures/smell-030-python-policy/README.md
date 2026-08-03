# smell-030-python-policy — POSITIVE for VG-SMELL-030 (Python, `medium`)

The same smell in Python, and the fixture that pins the DOWN-WEIGHT.

`AccessPolicy.is_allowed` decides. `TenantPolicy` narrows it. `ExportPolicy`
replaces it with `return True`.

Two things this fixture exists to hold still:

1. **`is_allowed` is an ambiguous name** — the corpus contains a `RateLimiter.
   isAllowed` and a `CircuitBreaker.isAllowed`, neither of which is access
   control. It is read as access control here only because the family carries
   authorization vocabulary: the directory is `policies/`.
2. **Nothing here is elevated.** No `admin`, no `owner`, no route. The finding
   is `medium` rather than `high`, which is what "down-weight rather than
   exclude" means for negative condition 8. Compare `smell-030-admin-controller`,
   which is `high` for the one reason this is not.

The docstring inside `ExportPolicy.is_allowed` is deliberate. An idiomatic
Python override is a docstring followed by one statement, and blanking keeps the
`"""` delimiters while emptying what is between them — so the blanked body is
`"""""" return True`, not `return True`. The rule strips the surviving
delimiters before comparing. Without that step the entire Python arm would be
blind to the language's house style, and no test asserting "no findings" would
have noticed.
