# smell-041-no-reach — VG-SMELL-041 NEGATIVE

A request value, a sanitizer and a database query in one function, and no flow
between them: the statement is built from a module constant.

Expected: **no `VG-SMELL-041`**, and **zero taint flows** — the one directory in
the group whose premise is the opposite of the others'.

Because "no flows" is exactly what an empty file would produce, the test also
asserts that `req.body`, `db.query(` and `sanitizeActor(` are still textually
present. A fixture that decayed into nothing would otherwise satisfy every
assertion and prove none of them.
