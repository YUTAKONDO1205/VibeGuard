# embedded-wired — VG-AISC-003 falsification corpus

Every security initializer here IS wired up, and each one uses a mechanism that
has no syntactic call site. A reachability-based analysis reports all of them;
this rule must report none.

- `crypto_engine_init` — referenced from a function-pointer table
- `rng_init` — referenced from a designated struct initialiser (`.init = ...`)
- `wdt_enable` — referenced from an RTOS task registration, with a cast
- `secure_boot_verify` — a `__attribute__((weak))` placeholder, whose whole
  purpose is to be defined and not called until an integrator overrides it

Expected: zero `VG-AISC-003` findings.
