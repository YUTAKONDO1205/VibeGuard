# smell-052-recursive-sanitizer — the positive that pins self-reference

`sanitizeCommentTree` writes its own name once, inside its own body, because it
walks a reply tree. That is the only occurrence of the identifier in the project
other than the declaration head.

A reference scan that counts occurrences without excluding the symbol's own body
concludes that something uses it — and every recursive function in every project
would be exempt from this rule for the same reason. A function that calls itself
has not been wired to anything.

`POST /comments` is registered with no guard and `req.body.text` reaches
`db.query`, so this is a finding: a sanitizer written for a comment tree, and a
comment endpoint that never passes anything through it.
