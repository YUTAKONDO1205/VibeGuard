# smell-052-orphan-sanitizer/ — the positive with no import to be missing

The two other positives put the unwired symbol in its own module, so "nobody
imports it" is part of what the analysis observes. This one deletes that clue:
`sanitizeUserInput` is declared in `api.ts`, **the same file that registers the
route and writes the SQL**, three lines above the handler that needed it. There
is no missing import, no unreferenced module, and no cross-file distance at all —
just a function whose name is written exactly once as a declaration and once in
an export list, and never as a call.

That makes this the directory that pins two things a simpler implementation gets
wrong:

- **A name inside an `export { … }` list is not a use.** Counting it as one would
  make this fixture silent, and would silence every project that exports at the
  bottom of the file instead of at each declaration.
- **The declaration is not exported with the `export` keyword.** `exportedNames`
  is what says the symbol leaves the file, not the modifier on its head.

**Expected: exactly one `VG-SMELL-052` finding, `high`** (`req.body.text` reaches
`db.query`) **at `low` confidence**.

`low`, and this is the third thing the directory pins. `server.ts` imports
`api.ts`, so something in the project holds a handle on the defining module —
which means a namespace object or a computed member access could reach
`sanitizeUserInput` without ever writing its name, and a lexical scan would never
know. The two other positives define their symbol in a module nothing imports at
all, where no such mechanism exists, and come out at `medium`. If this directory
ever reports `medium`, the confidence band has stopped distinguishing "nothing
could be calling it" from "nothing appears to be calling it".
