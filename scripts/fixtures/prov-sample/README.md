# PROV recorded sample corpus — NOT AN EXPERIMENTAL RESULT

Three hand-written Python files and a manifest, shipped so that
`scripts/sec-prov-gen-corpus.mjs` is executable end to end from a fresh
checkout:

```
node scripts/sec-prov-gen-corpus.mjs --manifest scripts/fixtures/prov-sample/manifest.json
node scripts/sec-prov-gen-corpus.mjs --selftest
```

**No model generated any of these files.** `m-recorded@v0` names nothing that
exists; the prompt-style axis is a label on three files a human wrote to give the
grid a gradient (two findings, one finding, zero findings). Any number derived
from this corpus and quoted as a measurement of a model, a prompt style or a
temperature is a fabrication, and the scorer stamps every output produced from
it with `resultStatus: "not-an-experimental-result"` and a paragraph saying so.

## What it is actually for

Two things a real corpus cannot do here, because no model API is reachable from
this machine:

1. **Keep the pipe honest.** The manifest exercises every validation the scorer
   performs — derived-vs-declared cell ids, grid completeness, per-file SHA-256
   content addressing, language agreement with the task spec, path containment.
   A regression in any of those shows up on a three-cell corpus in under a
   second.
2. **Prove the determinism claim.** `--selftest` runs the whole pipeline twice
   and byte-compares. Without a corpus in the repository that claim would be
   untestable by anyone who has not been handed a corpus.

## The real input

A real run takes a manifest produced elsewhere with
`corpusOrigin: "external-input"`, and the scorer marks its output
`resultStatus: "measurement"`. The manifest schema is documented in the header
of `scripts/sec-prov-gen-corpus.mjs`; the shape here is the smallest complete
example of it.

## Why the sources are in the repository and the outputs are not

The sources are inputs to a check and are tiny, so they are tracked — the same
arrangement as `scripts/fixtures/a2-egress/`. Outputs go to
`security-experiment/_results/`, which `.gitignore` excludes along with the rest
of `security-experiment/`.
