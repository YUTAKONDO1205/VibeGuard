# VibeGuard project instructions for Codex

## Goal
Build and evolve **VibeGuard**, a monorepo product that turns short natural-language ideas into validated, shippable increments.

The default development loop is:
1. clarify the user intent into a lean spec,
2. implement one scoped increment,
3. validate it with tests and browser checks,
4. report what is done, what was verified, and what remains.

## Operating model
Codex only spawns subagents when explicitly asked to do so, so this repository uses an intentional three-role workflow:

- **planner**: expands vague requests into a sprint-sized implementation plan.
- **generator**: implements one approved slice with the smallest defensible change set.
- **evaluator**: verifies behavior with tests, static checks, and browser-based flows.

For any non-trivial feature, bug, or refactor, the root agent should explicitly delegate in this order:

1. Ask **planner** to turn the request into a concrete build plan.
2. Ask **generator** to implement exactly one sprint/task from that plan.
3. Ask **evaluator** to verify the delivered behavior before claiming completion.

Do not skip evaluation for user-facing work, auth, persistence, billing, or workflow automation.

## Delegation rules
### Use planner when
- the user request is ambiguous,
- the work spans multiple files or layers,
- schema/API/UI decisions are involved,
- you need to break a large request into phases.

Planner output should usually include:
- objective,
- assumptions,
- scope and non-goals,
- affected packages/apps,
- API/data model changes,
- UI states and edge cases,
- acceptance criteria,
- a sequence of implementation tasks small enough for one generator pass each.

### Use generator when
- there is a clear task to build,
- you can keep the change bounded,
- you know the acceptance criteria.

Generator must:
- make the smallest change that satisfies the task,
- preserve existing architecture unless the plan explicitly changes it,
- update tests when behavior changes,
- avoid unrelated cleanup,
- leave a concise implementation summary for the parent agent.

### Use evaluator when
- code changed,
- UX changed,
- APIs, DB, auth, jobs, or workflows changed,
- regressions are plausible.

Evaluator must:
- run the most relevant automated checks first,
- use Playwright MCP for real browser validation when UI or flows changed,
- capture failures precisely,
- distinguish between verified behavior and unverified assumptions,
- return either PASS, PASS WITH GAPS, or FAIL.

## Definition of done
A task is done only when all of the following are true:
- acceptance criteria are satisfied,
- relevant tests/checks pass,
- UI work is exercised in a browser when applicable,
- any new env vars, scripts, or migrations are documented,
- the final report states what changed, how it was verified, and residual risks.

## Monorepo expectations
Unless the existing repo clearly uses a different stack, prefer a structure like:

- `apps/web` for the frontend
- `apps/api` for the backend
- `packages/ui` for shared UI primitives
- `packages/shared` for shared types/schemas/utils
- `packages/config` for lint/type/test config
- `docs/` for specs, decisions, and runbooks

Prefer TypeScript-first implementations for shared logic.
Prefer explicit schemas and typed boundaries for API contracts.
Prefer incremental migrations over sweeping rewrites.

## Testing expectations
At minimum, choose the smallest set that gives confidence:
- unit tests for pure logic,
- integration tests for API/data boundaries,
- end-to-end or browser validation for key flows.

If full validation is blocked, say exactly what is blocked and how to unblock it.

## Reporting format
When finishing a delegated unit of work, report in this shape:
- What changed
- Files or modules touched
- Checks run
- Browser validation run or not run
- Open risks / follow-ups

## Migration note
This repo may still contain Claude-oriented instructions. Codex should treat `AGENTS.md` as the primary instruction file, but project config also allows fallback filenames so older project docs can remain during migration.
