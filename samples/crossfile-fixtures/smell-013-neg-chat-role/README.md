# smell-013-neg-chat-role

`role` is also the OpenAI chat-completion message field, and VG-SMELL-010
discovered by evaluation over real repositories that the collision is
concentrated in exactly this project's target population: a codebase that calls
an LLM is a codebase written with LLM help.

`last.role === 'assistant'` is followed by a 403 — a protocol refusal, not an
authorization one — so the denial condition does not save the rule here.
`SUBJECT_WORD` does: `last` names a message, not a subject. That is a positive
requirement rather than a blocklist of chat words, so receivers nobody has
enumerated (`element.role`, `node.role`, `row.role`) fall out with it.
