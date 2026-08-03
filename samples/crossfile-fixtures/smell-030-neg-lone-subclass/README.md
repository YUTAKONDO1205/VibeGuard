# smell-030-neg-lone-subclass — NEGATIVE for VG-SMELL-030 (condition d)

`RequestAuthorizer.authorize()` decides. `ExportAuthorizer` is its only subclass
in the project, and it overrides `authorize()` with `return true`.

Conditions (a), (b) and (c) all hold. The rule is silent because (d) does not:
there is no sibling, so there is no convention for this subclass to be the odd
one out of.

That is not a technicality. A base with one subclass that always allows is
indistinguishable — from the outside, and from the text — from a base whose
default was always meant to be permissive for this one specialisation. The
evidence that turns "this class returns true" into "this class is the odd one
out" is a sibling that still decides, and there is none here.

`AuditLogAuthorizer` in the same directory is deliberately NOT a subclass: it is
a standalone class with its own `authorize`, present so the fixture cannot pass
by having no other authorization code at all.
