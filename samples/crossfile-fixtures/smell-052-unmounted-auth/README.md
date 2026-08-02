# smell-052-unmounted-auth/ — the positive, in JavaScript and CommonJS

The same defect as `smell-052-unwired-validator/`, written the other way round on
three axes at once, because a rule that only works on the shape its author had in
mind is a rule that finds nothing in the wild:

- **JavaScript, not TypeScript.** The rule declares both languages; this is the
  directory that proves the second one is not decoration.
- **CommonJS, not ESM.** `requireAuth` is offered to other modules through
  `module.exports = { requireAuth }`, which is neither `export function` nor
  `export { … }`. A rule that decides "was this exported" by looking only for the
  `export` keyword never even considers this symbol.
- **A response sink, not a query sink.** `renderProfile` interpolates
  `req.query.name` into HTML and hands it to `res.send`. Untrusted input reaches
  a sink, so the finding is warranted — but the sink is not an injection sink, so
  the finding must come out at the base severity.

**Expected: exactly one `VG-SMELL-052` finding, `medium`.** If this directory
ever reports `high`, severity has stopped distinguishing "data reaches a
database" from "data reaches a response", and the field has stopped carrying
information.
