# compiler/provenance — signed evidence, build provenance, reproducible-build comparison

Three things, and one loudly declared non-goal.

1. A **detached signature** over the canonical evidence form, with a verifier
   that requires a trust anchor and refuses to run without one.
2. **Build provenance** in the SLSA shape — subject digests, builder id,
   invocation, materials — where editing any recorded field fails verification.
3. A **clean-rebuild byte comparison**: the same fixture built twice from a
   clean state, compared byte for byte, with the cause of every difference
   identified rather than guessed. The measured result is in
   [`docs/rebuild-measurement.md`](docs/rebuild-measurement.md).

The non-goal is [diverse double-compiling and the trusting-trust
problem](#non-goal-diverse-double-compiling), which this component does not
attempt and must not be read as addressing.

This builds on the toolchain pin (`../driver/tools/make-pin.mjs`,
`../driver/lib/toolchain.mjs`) and on the evidence canonicaliser
(`../evidence/canon.mjs`). Neither is reimplemented here; both are imported.

---

## 1. What is signed

The signed bytes are `canonicalJson(record)` — the canonical text of the
record, exactly the bytes `evidenceDigest` is taken over (`../schema/interfaces.md`
§5). **Not** the file on disk.

Two reasons, and the second is the one that matters:

- the file is pretty-printed, so a reformat, a line-ending conversion or a
  re-serialisation in a different key order would break a signature over raw
  bytes while changing nothing that was claimed;
- signing the canonical form means "the signature verifies" and "the digest
  matches" cannot come apart. Over different inputs there would be two notions
  of *this record*, and a checker holding two of those can be made to disagree
  with itself.

### The hole rule 1 creates, and `contextDigest`

Rule 1 removes the top-level `context` subtree before digesting. That is
correct — `context` is where everything a re-run cannot reproduce lives — but it
means a signature over the canonical text says **nothing** about `context`.
`generatedAt`, the host block, the recorded time source: all editable, with both
the digest and the signature still checking out.

So the record carries `contextDigest`: a top-level field, therefore digested,
therefore signed, holding the SHA-256 of the canonical text of the `context`
subtree. The excluded subtree is committed to by an included field; the
exclusion rule is untouched; an edit to `context` is caught as `VG-ART-124`.

There is a test that demonstrates both halves of this: it edits `context`,
asserts the canonical text did **not** move and the signature still verifies —
the hole is real — and then asserts `contextDigest` no longer matches.

### Algorithm

Ed25519. RFC 8032 signatures are deterministic: the same key over the same
message produces the same 64 bytes every time. A signature that changed on every
run would make a signed record non-reproducible, which is the opposite of what
the rest of this toolchain is for.

### The envelope

`<record>.sig.json`, detached, next to the record:

```json
{
  "algorithm": "ed25519",
  "canonicalDigest": "<sha256 of the signed bytes>",
  "keyId": "<sha256 of the public key's SPKI DER>",
  "payload": { "bytes": 2223, "kind": "evidence-canonical-text" },
  "publicKey": "<base64 SPKI DER>",
  "signature": "<base64>",
  "sigVersion": "detached-sig-v0",
  "subject": { "evidenceDigest": "…", "file": "provenance.json" }
}
```

The envelope carries the public key **for convenience only**. The verifier takes
its trust anchor from `--public-key` and compares; there is no code path that
falls back to the key inside the signature. Checking a signature against the key
that came with it establishes that the document is self-consistent, which is a
property every forgery has. Without `--public-key` the verifier exits 3 (could
not complete), not 0.

---

## 2. Key management, and what a key holder can do

**Key management is not the research contribution here, and pretending
otherwise would be the dishonest part.** The key pair is generated locally, on
demand, into a directory the caller names (`tools/keygen.mjs`). No private key
is committed. The test suite generates its own into a temporary directory and
deletes it; there is no fixture key, so the suite could be run against a real
signer unchanged.

In a deployment the key would live in an HSM, a KMS or a short-lived workload
identity. None of those changes anything below.

### What an attacker who holds the private key can do

**Everything the signer can do.** Concretely, and this is not hedged:

| They can | Caught by |
|---|---|
| Write any provenance they like and sign it. Every layer-1 check passes: valid signature, matching digests, intact context. | Nothing in layer 1. |
| Claim a different commit sha. | Only `--expect-commit`, which compares against a sha the verifier was given independently. |
| Claim a different toolchain. | Only `--pin`, which recomputes the digest from a pin file the verifier was given independently. |
| Claim digests for artefacts they never built. | Only `--artifact-root`, which rehashes the bytes. |
| Re-sign a record after editing `context`. | Nothing. `contextDigest` is recomputed and re-signed along with everything else. |
| Backdate `generatedAt`. | Nothing. A timestamp a local process wrote is not evidence of when anything happened, signed or not. |

The signature is therefore **not** what makes the claims true. It binds a
document to a key holder. Everything the verifier can re-derive from the world
it re-derives, precisely because a signature over a false statement is a valid
signature.

That is why every check the caller did not enable is reported as `NOT_OBSERVED`,
by name, at the end of every run — including successful ones — and why
`--strict` turns any `NOT_OBSERVED` into exit 3. A clean exit over three checks
nobody made looks exactly like a clean exit over six, and the difference is the
entire security value.

### What is protected without the key

An attacker who does **not** hold the key cannot change any digested field: the
commit sha, the toolchain digest, any subject digest, the builder id, the
materials list. Every such edit produces `VG-ART-120` (signature does not
verify), `VG-ART-121` (the signature covers other bytes) and `VG-ART-123`
(`evidenceDigest` does not re-derive) — measured, not asserted; see §7.

---

## 3. The provenance shape

An in-toto Statement carrying a `slsa.dev/provenance/v0.2` predicate. v0.2
rather than v1 because v0.2 is the version whose field names are literally
`builder.id`, `invocation` and `materials`. v1 is a better model and a worse fit
for a claim that has to be checked field by field. `PREDICATE_TYPE` in
`lib/statement.mjs` is the only place the choice is written down.

```
subject[]                        what was built: relative name + sha256
predicate.builder.id             urn:vibeguard:builder:local-compiler-toolchain:v0
predicate.buildType              urn:vibeguard:buildtype:pinned-clang-fixture:v0
predicate.invocation
        .configSource.uri        where the build description came from
        .configSource.digest.sha1  THE COMMIT SHA
        .configSource.entryPoint what was run
        .parameters              compile flags, as strings
        .environment             platform, arch, node, sourceDateEpoch
predicate.materials[]            every digested input. materials[0] is always
                                 urn:vibeguard:material:toolchain-pin — THE
                                 TOOLCHAIN DIGEST
predicate.metadata.completeness  which of the three blocks are populated
predicate.metadata.reproducible  true / false / null. null is "not observed"
                                 and is never written as false.
```

**A URN and not an `https://` URI for the builder.** This builder is a local
process with no hosted identity. Minting a URL for it would assert an authority
that does not exist; a URN says "a name, not a location".

### Two deliberate divergences from the SLSA schema

Both are here rather than left to be discovered:

1. **No `metadata.buildStartedOn` / `buildFinishedOn`.** Those are wall-clock
   strings, and SLSA puts them inside the predicate — that is, inside the
   digested region. The evidence rules put anything a re-run cannot reproduce
   into `context`, which is excluded from the digest and committed to by
   `contextDigest`. Timestamps therefore live in `record.context`, not in the
   statement. Putting them where SLSA does would make every record digest
   differently from every other record of the same build.
2. **The statement is carried inside a record, not sealed directly.** Sealing
   the Statement itself would add `context` and `evidenceDigest` as top-level
   members of it: neither a valid Statement nor an honest evidence record. So
   `record.statement` holds the Statement whole and byte-exact, and can be
   lifted straight back out for an in-toto consumer.

---

## 4. Finding IDs

Bands claimed by this component, following the precedent in
`../evidence/README.md` (which took `VG-ART-050`–`069`):

| Band | Meaning |
|---|---|
| `VG-ART-120`–`129` | signature, digest and statement integrity |
| `VG-CFG-030`–`039` | provenance disagreeing with the pin or with the checkout |

**Why 120 and not 070.** This component was written at the same time as several
others in `compiler/`, and the low bands filled up while it was being written:
`070`–`079` and `080`–`092` were both taken by peer components before this one
was finished. Rather than argue about who was first, this band starts well clear
of every allocation that existed when it was chosen. If a peer has since claimed
`120`–`129` as well, this is the file to change and there is exactly one place
in the code to change it (`ART` in `lib/verify-core.mjs`).

`VG-CFG` for the last two because `../schema/interfaces.md` §2 assigns "a
toolchain digest does not match the pin" to that namespace explicitly. The
driver's own allocation ran to `VG-CFG-019` at the time of writing, so `030`
leaves it room.

| ID | Meaning | Class |
|---|---|---|
| `VG-ART-120` | The detached signature does not verify | integrity |
| `VG-ART-121` | The signature is over bytes this record does not produce | integrity |
| `VG-ART-122` | The signature was made by a key this verifier does not trust | integrity |
| `VG-ART-123` | `evidenceDigest` does not match a re-derivation | integrity |
| `VG-ART-124` | The `context` subtree has been altered since sealing | integrity |
| `VG-ART-125` | The statement is missing a required SLSA field | finding |
| `VG-ART-126` | A subject's bytes do not match the recorded digest | finding |
| `VG-ART-127` | The record states two different toolchain digests | finding |
| `VG-ART-128` | The detached signature is malformed | integrity |
| `VG-ART-129` | The file is not a provenance record | integrity |
| `VG-CFG-030` | The recorded toolchain digest is not the pin's | integrity |
| `VG-CFG-031` | The recorded commit is not the one it was checked against | finding |

## 5. Exit codes

`../schema/interfaces.md` §7, with the mapping this component uses:

| Code | Here |
|---|---|
| 0 | everything asked for was checked and held |
| 2 | the record verified cryptographically and disagrees with the world |
| 3 | could not complete: no trust anchor, an unreadable file, an empty input set, or `--strict` with a check the caller gave no way to make |
| 4 | the trust chain failed — signature, key, digest, `context`, or the pin |

**Precedence, because it is a decision and not an accident: 4 > 3 > 2 > 0.**
Integrity outranks everything because nothing else about the record means
anything once it fails. Incomplete outranks findings because findings drawn from
a partially-checked set are not a verdict about the set — the findings are
printed either way.

## 6. Counting contract

Every runner prints exactly one line of the form

```
inputs=N checked=N skipped=S
```

and exits non-zero when `N` is 0 unless `--allow-empty` was passed. Two further
invariants are enforced rather than trusted: `checked + skipped === inputs`, and
every skip is **named** in the output. A count of skips tells a reader how much
was not done and not *what*.

**Skip is not pass.** A missing prerequisite tool fails the run. It becomes a
skip only when `PROVENANCE_ALLOW_MISSING_TOOLS` is set, and then every skipped
case is listed by name. `tools/rebuild-compare.mjs` with no compiler installed
exits 3 and says so; with the variable set it exits with
`skipped: same-path-clean (clang-18 is not installed; PROVENANCE_ALLOW_MISSING_TOOLS authorised the skip)`.

## Property states

`../schema/interfaces.md` §3. Each check in a verification carries a state:
`PRESENT`, `ABSENT`, `NOT_OBSERVED`, `NOT_APPLICABLE`.

`LOST` and `REINTRODUCED` never appear, and that is a fact about the observation
rather than an abbreviation of the vocabulary: both are defined relative to an
**earlier** observation of the same property, and verifying one record is a
single point. A caller verifying a sequence keeps the whole sequence of
`checks[]` arrays — never collapsing it, never stopping at the first `ABSENT` —
and derives `LOST`/`REINTRODUCED` across them.

---

## 7. What has been measured

Every row below was produced by running the code. Nothing here is inferred from
reading it. The runs were done on Linux (WSL, Ubuntu 24.04, node 18.19.1,
clang 18.1.3) with the fixture built into a scratch directory on the Linux
filesystem, never under `compiler/`.

| Claim | How |
|---|---|
| 55 tests pass on Windows (node 24) and on Linux (node 18); 0 fail, 0 skip | `node --test compiler/provenance/test/*.test.mjs` |
| A real pin, real artefacts, a locally generated key: 12 checks, all `PRESENT`, exit 0 | `make-pin.mjs` → build → `make-provenance.mjs` → `verify-provenance.mjs --strict` |
| The commit sha edited on disk: `VG-ART-120`/`071`/`073` + `VG-CFG-031`, exit 4 | one `sed` over the written record |
| The toolchain digest edited on disk: `VG-ART-120`/`071`/`073` + `VG-CFG-030`, exit 4 | same |
| One byte of the linked binary flipped: `VG-ART-126`, exit 2 — the record itself still verifies | `dd` over `app` |
| A record re-signed by a different key: `VG-ART-122`, exit 4, even though the forgery is internally consistent | `keygen` + `sign-evidence` with the rogue key |
| A `context` edit moves nothing in the canonical text, the signature still verifies, `VG-ART-124` catches it | unit test |
| A key holder re-signing a false commit or a false toolchain passes every layer-1 check and is caught only by `--expect-commit` / `--pin` | unit test |
| An empty directory: `inputs=0 checked=0 skipped=0`, exit 3; with `--allow-empty`, exit 0 with a line saying it proves nothing | `verify-provenance.mjs --dir <empty>` |
| No compiler installed: exit 3 with "that is a failure, not a skip"; with the environment variable, a named skip | `rebuild-compare.mjs --cc clang-does-not-exist-18` |
| The fixture is not vacuous: target memset call sites `-O0`=1 `-O2`=0, control `-O0`=1 `-O2`=1, declarations 1 at both — 2 call sites vs 1 across the module | `rebuild-compare.mjs`, every case |
| 7 of 11 rebuild cases reproduce byte-for-byte; 4 differ, each for an identified reason | [`docs/rebuild-measurement.md`](docs/rebuild-measurement.md) |

### The oracle

Every measurement here counts the **zeroing call site**, never the symbol name,
and counts it **within one IR unit** (`../schema/interfaces.md` §4). A deleted
call leaves `declare void @llvm.memset.p0.i64(...)` behind; a name search
therefore keeps reporting the effect as present until some later pass sweeps the
declaration away, and then blames the sweeper.

`lib/ir-oracle.mjs` implements the rule and `test/ir-oracle.test.mjs` includes
the exact IR that defeats the naive version: at `-O2` the naive count is 2 (one
call, one declaration) and the correct count is 1.

The fixture carries a **control** whose zeroing cannot be removed —
`control_wipe` hands a zeroed global to a function in another translation unit —
and the runner refuses to report a reproducibility comparison from a build in
which the control's count fell to zero. That matters twice over here: an
artefact with nothing in it reproduces perfectly and proves nothing.

---

## 8. Reproducibility, in one paragraph

Two clean builds of the same fixture on the same machine are byte-identical when
nothing varies, **including with `-g`**. They stop being identical when a path
the compiler was asked to record changes: with `-g`, moving the build directory
moves `DW_AT_comp_dir` and moving the source directory moves `DW_AT_name`, both
landing in `.debug_str`/`.debug_line_str`. Without `-g` neither move is visible
in the output at all. `__FILE__` puts the path into `.rodata`, where no
debug-info switch reaches it. `__DATE__`/`__TIME__` put the clock there too, and
`SOURCE_DATE_EPOCH` removes that difference — measured, not assumed. Applying
`-ffile-prefix-map` and `-fdebug-compilation-dir=.` makes the `-g` case
reproduce again, which is what turns "the path is probably the cause" into "the
path is the cause". `.note.gnu.build-id` differs only when something else
already did; it is a consequence and the runner labels it as one. Full table,
including the DWARF attributes and the exact strings, in
[`docs/rebuild-measurement.md`](docs/rebuild-measurement.md).

---

## Non-goal: diverse double-compiling

**Diverse double-compiling, and the trusting-trust problem it addresses, are out
of scope for this component. Nothing here attempts them and nothing here should
be cited as evidence about them.**

The distinction is worth stating precisely, because the two are easy to conflate
and this component sits next to one of them:

- What is done here is **reproducibility**: does building the same source with
  the same pinned toolchain twice produce the same bytes? That is a statement
  about the build being a function of its recorded inputs. Every check in this
  directory is downstream of trusting the compiler binary that the pin names.
- What is **not** done here is establishing that the pinned compiler binary
  corresponds to its own source — that it contains no behaviour the source does
  not describe. Reflections on Trusting Trust is the statement of the problem;
  diverse double-compiling (Wheeler) is the known technique, and it requires
  compiling the compiler's source with a second, independently produced compiler
  and comparing the results. It needs a diverse trusted compiler, a bootstrap of
  the compiler under test from source, and an argument about the environment
  that is considerably larger than anything in this directory.

Why it is declared rather than attempted: a partial attempt is worse than none.
Rebuilding clang once with gcc and observing that the outputs differ — which
they would, for all the ordinary reasons in
[`docs/rebuild-measurement.md`](docs/rebuild-measurement.md) — produces a
negative result that means nothing, and a reader who saw the attempt would
reasonably conclude the question had been examined. It has not been. The
toolchain pin is a **statement about bytes**, not about what those bytes do, and
this component inherits that limit exactly.

Related limits, recorded for the same reason:

- **A signature says a key holder asserted something.** It is not attestation
  that the build happened as described. See §2.
- **The declared-versus-measured pin.** `declaredToolchainDigest` computes the
  digest from the pin file alone, without touching the filesystem, so a
  verification with `--pin` establishes that two documents agree about a pin —
  not that any binary on disk matched it. `verifyPinLive` in `lib/pin.mjs` does
  the second thing; it is not wired into the default verification path, and the
  check is therefore reported as what it is.

---

## Running it

```sh
# a key pair (never committed; the tests make their own in a temp directory)
node tools/keygen.mjs --dir <somewhere outside the repo>

# provenance over artefacts that already exist, signed
node tools/make-provenance.mjs \
     --artifact-root <build output dir> --subject app --subject wipe.o \
     --source src/wipe.c --pin <toolchain-pin.json> --repo <checkout> \
     --out <records/provenance.json> --key <signing-key.pem>

# verification. --public-key is required; the rest are the independent checks
node tools/verify-provenance.mjs \
     --public-key <signing-key.pub.pem> --record <records/provenance.json> \
     --pin <toolchain-pin.json> --expect-commit <sha> \
     --artifact-root <build output dir> --strict

# sign an evidence record produced by some other component
node tools/sign-evidence.mjs --key <signing-key.pem> --dir <evidence dir>

# the reproducibility matrix. --list shows the cases
node tools/rebuild-compare.mjs --work <scratch dir on the linux filesystem>
```

Builds and measurement output go to the Linux filesystem, never under
`compiler/` (`../schema/interfaces.md` §1).

## Layout

```
lib/keys.mjs          ed25519 key pair generation, loading, key ids
lib/signing.mjs       the canonical signing bytes, the envelope, verification
lib/statement.mjs     the SLSA v0.2 statement, and what is required of one
lib/record.mjs        the record that carries a statement, sealed by the canonicaliser
lib/pin.mjs           the toolchain digest, declared and measured
lib/verify-core.mjs   every check, with a state each, and the exit-code mapping
lib/ir-oracle.mjs     memset call sites per IR unit
lib/cli.mjs           the counting contract, in one place
tools/                keygen, make-provenance, sign-evidence, verify-provenance, rebuild-compare
fixtures/             wipe.c (target + control) and main.c
test/                 55 tests; no key material, no build required
docs/                 the rebuild measurement
```
