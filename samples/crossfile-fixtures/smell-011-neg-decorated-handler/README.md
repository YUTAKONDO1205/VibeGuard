# smell-011-neg-decorated-handler/ — the guard is on the handler, not the route

Three registrations carry `requireOwner`; a fourth carries nothing in its
middleware position and points at a method annotated `@UseGuards(OwnerGuard)`.

An empty middleware list is not the same as an unguarded route. Frameworks that
attach guards by annotation put them on the declaration instead, and a rule that
only reads the registration reports every one of them.

**Expected: no `VG-SMELL-011` finding.**
