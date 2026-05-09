# @vibeguard/remediation-engine

Renders the `why` / `how` / `exampleFix` text that ships next to each
finding. Pulls the static template off the rule's `remediation` block
and interpolates `${var}` placeholders from the rule match's
`variables` map.

## Public surface

- `buildRemediation(rule, match)` — returns the populated remediation
  object, or `undefined` if the rule has no template.
- Interpolation: `${target}` in the template is replaced by
  `match.variables.target`. Missing keys leave the placeholder visible
  (intentional — it surfaces template/match drift in tests).

## Why a separate package

The CLI default-ons remediation; the Chrome extension may turn it off
to keep payload small. Splitting the engine out lets the analyzer
return raw matches and the consumer choose whether to render them.
