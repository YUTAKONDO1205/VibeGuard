# @vibeguard/rules

The VibeGuard rule catalogue. Each rule is a `RuleDefinition` with a
syntactic regex matcher, a severity / confidence level, and remediation
text. Rules are intentionally narrow — VibeGuard biases toward high
precision over high recall.

## Layout

```
src/
├── rule-types.ts      # RuleDefinition / RuleMatch / RuleContext
├── matcher-utils.ts   # runRegex, languageMatches, indexToPosition, extractBlockAfter
├── confidence.ts      # context-window confidence correction + SEVERITY_CONFIDENCE_FLOOR
├── rules/
│   ├── injection.ts            # VG-INJ-NNN    — SQLi, RCE, XSS, deserialization, proto pollution
│   ├── auth.ts                 # VG-AUTH-NNN   — debug bypass, CSRF, TLS, session
│   ├── secrets.ts              # VG-SEC-NNN    — AWS keys, PEM, GH tokens, generic API keys
│   ├── crypto.ts               # VG-CRYPTO-NNN — weak hash, weak random, plaintext HTTP
│   ├── framework.ts            # VG-FW-NNN     — Django/Flask/Express misconfig
│   ├── quality.ts              # VG-QUAL-NNN   — AI-quality / placeholder / stub patterns
│   ├── design-smells-single.ts # VG-SMELL-NNN  — single-file design smells
│   ├── ai-supply-chain.ts      # VG-AISC-NNN   — hallucinated dependencies (+ -data.ts: the known-package set)
│   ├── lang-c.ts               # VG-MEM-NNN    — C/C++ memory
│   ├── embedded-ai.ts          # VG-EMB-NNN    — AI-generated embedded/firmware patterns
│   ├── embedded-rtos.ts        # VG-RTOS-NNN   — ISR / concurrency
│   └── lang-{go,java,php,ruby}.ts  # per-language arms of the families above
└── index.ts           # allRules, getRule, getRulesForLanguage
```

The cross-file rules are **not** here — they need the whole project rather than
one file and live in `@vibeguard/analysis-graph`, behind `--include-design-smells`.

## Rule ID convention

```
VG-<FAMILY>-NNN
```

`FAMILY` is one of `INJ`, `AUTH`, `SEC`, `CRYPTO`, `QUAL`, `FW`, `SMELL`,
`AISC`, `MEM`, `EMB`, `RTOS`. The prefix groups rules by structural family
(which file they live in); the `category` field on the rule carries the risk
taxonomy and is what the SARIF / Markdown output groups by. They overlap but
don't have to match 1:1 — see `registry.test.ts` for the asserted invariants.

Two families are numbered across both packages, because the split is by
analysis scope rather than by subject: `VG-SMELL-003/004/012`, `VG-AISC-001`
and `VG-RTOS-001/002/004` are single-file rules defined here, while
`VG-SMELL-010`, `VG-AISC-002/003` and `VG-RTOS-003` are their cross-file
counterparts in `analysis-graph`. A rule ID is unique across the two; the
number does not tell you which package it is in.

## Adding a rule

1. Pick or create the right file under `rules/`.
2. Export a `RuleDefinition`. Keep the regex narrow; comment why each
   alternation arm exists.
3. Register the rule in the file's exported array (e.g. `frameworkRules`).
4. Add tests to `rules.test.ts` — at least one positive case, one
   negative case, and one comment-shielded case.
5. Add a paired sample under `samples/vulnerable` (and ideally one
   counterpart under `samples/safe` if there's a near-miss to guard).

The samples gate in CI fails if `samples/safe` produces any finding or
`samples/vulnerable` produces fewer than the threshold count.
