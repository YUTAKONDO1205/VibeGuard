# compiler/

A native toolchain workspace: a compiler driver and the Clang/LLVM plugins it
loads, used to check that security-relevant properties a source file states are
still present in the object file and the linked binary.

It is **not** part of anything VibeGuard ships. The GitHub Action, the VS Code
extension, the Open VSX listing and the Chrome extension are built from the
TypeScript workspaces and behave identically on a machine where this directory
was never built. Keeping that true is the point of the rules below.

## Boundaries

| Rule | Why | Enforced by |
|---|---|---|
| Outside the npm workspace globs (`packages/*`, `apps/*`, `extensions/*`) | otherwise `npm ci` and `npm run build` acquire a clang/LLVM prerequisite, and every CI job for the four channels fails on machines that do not have one | `scripts/check-packaging-invariants.mjs`, invariant 7a |
| No workspace declares a dependency on it | same reason, arriving through `file:`/`link:` instead of through a glob | invariant 7b |
| No shipped source imports from here | a user installing an editor extension has not agreed to install a compiler | invariant 7c (source) and 3b (the built bundles) |
| Build products are never committed | they are machine-specific and large, and history here is not rewritten — a force-push would break every installed consumer | `.gitignore` + invariant 7d |
| Measurement inputs and outputs stay out | they carry absolute paths and per-machine toolchain digests | invariant 7d |
| No network | the toolchain reads and writes local files, nothing else | invariant 7d (source-level tripwire) |

Two things the invariants do **not** cover, recorded so they are decisions
rather than oversights:

- **Zero-egress here is a source-level tripwire, not the runtime assertion.**
  The four shipped channels get a real one: their packaged bytes are executed in
  a network namespace on every push. Nothing equivalent exists for a native
  build, so what is enforced here is "no socket headers, no network modules, no
  fetching build description" — weaker, and named as weaker.
- **A new package under `packages/` is not automatically fenced.** The bundle
  probe knows which packages are CLI-only by name. When the evidence packages
  land, add them to `CLI_ONLY_PACKAGES` and `CLI_ONLY_PATH_TOKENS` in the same
  commit, or the extension bundles stop being checked for them.

Run them all with:

```
node scripts/check-packaging-invariants.mjs --pre-build   # source-only, no build needed
node scripts/check-packaging-invariants.mjs               # adds the built-bundle checks
```

The source-only subset already runs in CI on every push, before `npm run build`,
so a boundary violation is reported in seconds rather than at release time.

## Licence

This directory is **Apache-2.0 WITH LLVM-exception** (see `LICENSE`), not the
MIT of the repository root, because it compiles and links against the Clang and
LLVM development headers. No LLVM source is vendored here; the headers and
libraries come from a locally installed toolchain. The root `NOTICE` states the
per-directory terms.

## Building

Not built by `npm run build`, by design. It needs a local LLVM development
install (`llvm-<N>-dev`, `libclang-<N>-dev`, `cmake`, `ninja`) and is built out
of band. Pin the toolchain rather than assuming the distribution's current
version: two builds of "the same version" are not necessarily the same bytes,
which is why the pin records package versions *and* per-package digests.

## This directory is inside the scanner's own severity gate

Measured 2026-08-06, and worth knowing before writing the driver: the security
workflow scans the repository root and fails a pull request on `high`. It does
not exclude `compiler/`, and the C/C++ rules are live — a file here containing
`assert(is_admin(user));` produces `VG-AUTH-008` at `high` and turns the PR red.

That is the tool working, not a misconfiguration, and the answer is to write the
check as ordinary fail-closed control flow rather than to add an exclusion. An
authorization decision inside `assert` disappears under `NDEBUG`, which is
exactly the class of disappearance this directory exists to detect; a driver that
enforced its plugin policy that way would be the first thing it should catch.

## Before pushing

`npm test` and the invariants above do not know about C++. What they do know is
whether this directory has started to leak into the parts that ship, and that is
the failure worth catching early — a broken plugin is visible immediately, a
broken boundary is visible one release later.
