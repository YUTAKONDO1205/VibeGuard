# smell-052-neg-class-guard — the framework-discovered class negative

`RequireAdminGuard` is a class and its name is in the rule's vocabulary
(`require` + `admin` + `guard`). Nothing in the repository names it, because the
framework finds guards by globbing `security/*.guard.ts` at boot — the mechanism
Nest's discovery service, fastify-autoload and Angular's route loading all use.

A class is reached by CONSTRUCTION, and every mechanism that constructs one
without naming it (a DI container reading decorator metadata, a string provider
token, a directory glob) is this analysis's blind spot. Reporting an unnamed
class as unwired is reporting the blind spot as a defect.

The routing and taint conditions are both satisfied here, so removing the class
exclusion makes this directory fire on a guard that runs on every request.
