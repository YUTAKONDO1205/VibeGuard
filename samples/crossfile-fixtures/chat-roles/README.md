# chat-roles — VG-SMELL-010 falsification (LLM message role, not privilege)

Three comparisons against `.role` across two files, which is exactly the count
and spread the rule fires on — except none of them is an authorization decision.
The OpenAI-style chat completion API names its message field `role` and fills it
with `system` / `user` / `assistant` / `tool`, colliding with the property name
this rule reads as a privilege level.

This collision matters more than a generic false positive: it concentrates in
codebases that call an LLM, which is the same population as codebases written
with LLM help — the corpus this project is about. It was found by evaluation
over real repositories, not by review.

Expected: zero `VG-SMELL-010` findings.
