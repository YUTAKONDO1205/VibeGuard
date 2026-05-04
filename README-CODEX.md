# Codex-ready harness for VibeGuard

This package converts the attached Claude-oriented multi-agent design into a Codex-native layout.

## Included files
- `AGENTS.md`
- `.codex/config.toml`
- `.codex/agents/planner.toml`
- `.codex/agents/generator.toml`
- `.codex/agents/evaluator.toml`

## What changed from the Claude-style version
- `CLAUDE.md` 중심 instructions were migrated to `AGENTS.md`.
- Subagent roles were expressed as Codex custom agents under `.codex/agents/`.
- Project config was moved into `.codex/config.toml`.
- Playwright browser validation was wired through MCP so evaluator can do real UI checks.
- A fallback to `CLAUDE.md` remains enabled during migration.

## Recommended usage pattern in Codex
Use prompts that explicitly ask Codex to spawn the agents, for example:

### Feature planning
Ask planner to turn this request into a sprint-sized implementation plan with acceptance criteria and generator-sized tasks: <your request>

### Build one slice
Use generator to implement task 1 from the current planner output. Keep the change minimal and list files touched plus checks run.

### Validate
Use evaluator to verify the implemented slice. Run the most relevant tests first and use Playwright MCP for any changed user flow.

### End-to-end loop
Have planner create the plan, generator implement only the first task, then evaluator validate it and summarize any gaps before moving to task 2.

## Notes
- Codex does not automatically spawn subagents; prompts should ask for them explicitly.
- If your repo already has a `CLAUDE.md`, keep it during migration or merge the remaining useful rules into `AGENTS.md`.
- If your repo uses a different stack or folder layout, keep the agent roles and replace only the repo-specific conventions.
