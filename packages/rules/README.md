# @vibeguard/rules

The VibeGuard rule catalogue. Each rule is a `RuleDefinition` with a
syntactic regex matcher, a severity / confidence level, and remediation
text. Rules are intentionally narrow — VibeGuard biases toward high
precision over high recall.

## Layout

```
src/
├── rule-types.ts      # RuleDefinition / RuleMatch / RuleContext
├── matcher-utils.ts   # runRegex, languageMatches, indexToPosition
├── rules/
│   ├── injection.ts   # VG-INJ-NNN  — SQLi, RCE, XSS, deserialization
│   ├── auth.ts        # VG-AUTH-NNN — debug bypass, CSRF, TLS, session
│   ├── secrets.ts     # VG-SEC-NNN  — AWS keys, PEM, GH tokens, generic API keys
│   ├── crypto.ts      # VG-CRYPTO-NNN — weak hash, weak random, plaintext HTTP
│   ├── framework.ts   # VG-FW-NNN   — Django/Flask/Express misconfig
│   └── quality.ts     # VG-QUAL-NNN — AI-quality / placeholder / stub patterns
└── index.ts           # allRules, getRule, getRulesForLanguage
```

## Rule ID convention

```
VG-<FAMILY>-NNN
```

`FAMILY` is one of `INJ`, `AUTH`, `SEC`, `CRYPTO`, `QUAL`, `FW`. The
prefix groups rules by structural family (which file they live in); the
`category` field on the rule carries the risk taxonomy and is what the
SARIF / Markdown output groups by. They overlap but don't have to match
1:1 — see `registry.test.ts` for the asserted invariants.

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
