# smell-041-parameterized — VG-SMELL-041 NEGATIVE

**The correct shape the first version of the rule fired on, in both orders.**

```js
const id = req.query.id;
const rows = await db.query('SELECT name FROM customers WHERE id = $1', [id]);
res.send(`<h1>${escapeHtml(id)}</h1>`);
```

A parameterised statement for the database and an HTML escape for the page is the
most common correct Express handler there is. The first version of VG-SMELL-041
reported it whichever order the two lines were in — and it is the shape the
rule's own `remediation.exampleFix` recommends.

Expected: **no `VG-SMELL-041`**, with **taint flows present** (four: each
function's value reaches both of its sinks).

Falsifies: `sinkIsParameterized`. Removing it turns `showCustomer` into an
INVERTED finding and `showInvoice` into a BYPASSED one — two different branches
of `judge`, which is why both functions are here.

## ★ Why H1's flow is not the evidence it looks like

`analyzeProjectTaint` reports a flow into `db.query('… = $1', [id])` because `id`
appears in the argument list. That is exactly what H1 promises and it is not what
this rule needs: the question is whether the value reached the STATEMENT.
`sinkIsParameterized` answers it by comparing `StructureIndex.blanked` with
`SourceFile.content` at the same offsets — blanking is length-preserving, so a
character that is `$` in one and a space in the other was inside a string
literal. That is what separates the `?` of `'WHERE id = ?'` from the `?` of a
ternary without lexing anything.
