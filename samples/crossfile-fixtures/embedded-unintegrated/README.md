# embedded-unintegrated — VG-AISC-003 positive case

`crypto_engine_init` is defined in `crypto.c`, declared in `crypto.h`, and named
nowhere else in the project. The only other mention is inside a comment in
`main.c`, which the analysis blanks before searching — a comment is not a call.

Expected: exactly one `VG-AISC-003` finding, on `crypto.c`.

`sensor_init` is deliberately present and deliberately NOT flagged: it is called
from `main`, and it is not on the security-initializer allowlist either.
