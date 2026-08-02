# smell-052-mixed-language — the polyglot positive

A TypeScript service with a Python batch job beside it. `validateUploadPayload`
is the finding: exported from `middleware/`, referenced by nothing, and the
upload endpoint it was written for carries `req.body.filename` into `db.query`
with no guard mounted.

`jobs/verify_upload.py` defines `validate_request_payload`, which is in the
rule's vocabulary, is exported by Python's convention (no leading underscore),
and is referenced by nothing either. It must NOT be reported. The rule's taint
module returns nothing for Python — a Python arm needs its own sink table, not a
branch added to a regex — so a Python finding here would be a claim made with no
evidence behind it, and it would be filed under a rule whose remediation is
"add it to the argument list of an Express registration".

The per-file language filter is what stops it. `runCrossFileRules` only checks
that SOME file in the project is TypeScript or JavaScript, which this project
satisfies, so the project-level gate does not help here.
