# A2 negative-control fixtures (seeded violations)

Each `seeded-*.js` file contains exactly one deliberately planted network sink.
`scripts/sec-a2-egress-scan.mjs --mode control` runs them through the same
`scanSource()` the real distributables go through and asserts every one is
caught. Without this, "0 sinks in dist/" is indistinguishable from "the
detector is broken", and the A2 claim would be unfalsifiable.

`seeded-html-*.html` and `seeded-css-*.css` are the markup leg (A2-GAP-3). Three
of them egress with **zero JavaScript** — a remote `<script src>`, an `<img>`
pixel, a `<link rel=preconnect>` — and two more do it from a stylesheet via
`url()` and `@import`. They exist because `extensions/chrome/dist` ships
`sidepanel/index.html` and `sidepanel/index.css`, which the JS-only scanner
never opened: the zero it reported for them was the zero of not having looked.
`seeded-html-inline-script.html` pins the boundary between the two legs — its
sink is real JavaScript inside `<script>`, so it must be caught by the AST, not
by a URL regex.

`decoy-rule-pattern.js` is the opposite control. It contains the words `fetch`,
`XMLHttpRequest`, `require('https')` — but only inside string literals, exactly
the way `packages/rules/` carries them as detection patterns. A grep-based
implementation flags it; the AST implementation must not. It is the fixture
that proves the choice of an AST over a grep was load-bearing rather than
decorative. `decoy-local-refs.html` and `decoy-local-assets.css` do the same job
for markup: relative paths, `data:` URIs, a fragment link, and prose and rule
payloads that *mention* remote URLs. If the markup leg fired on any of those it
would be unusable on the real side panel, and an unusable check gets excluded
from CI rather than fixed.

Every fixture must be listed in `CONTROL_EXPECTATIONS`; an undeclared `.js`,
`.html` or `.css` file in this directory fails the control run on purpose.

All seeded destinations use the `.invalid` TLD (RFC 6761), which can never
resolve, so a fixture that somehow did execute could still reach nobody.

These files are never bundled, imported, or executed. They exist to be parsed.
