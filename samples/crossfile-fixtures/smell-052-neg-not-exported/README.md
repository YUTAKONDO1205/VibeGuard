# smell-052-neg-not-exported — the private-helper negative

`validateCommentBody` is a file-local function. Nothing outside
`middleware/validate-comment-body.ts` can name it, so "nobody else names it" is
not evidence that a connection is missing — it is how a private function
behaves, and every module in every codebase contains several.

Everything else the rule needs is present: `POST /comments` is registered with no
guard, `req.body.text` reaches `db.query`, and the identifier is in the rule's
vocabulary. Only the export condition is missing. `logRejection` — exported from
the same file — is there so the file has an export surface for the rule to read
and correctly decline to find the validator in.
