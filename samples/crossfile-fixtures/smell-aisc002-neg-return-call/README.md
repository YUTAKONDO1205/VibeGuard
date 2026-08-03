# `smell-aisc002-neg-return-call` — a system library reached only through calls

**VG-AISC-002 must stay silent here.** This is CORRECT code: every `SSL_*`
function it names is a real OpenSSL function declared in `<openssl/ssl.h>`, a
system header the analysis cannot resolve and does not pretend to.

## What it falsifies

The rule fires when a call is an undeclared member of a family the project's own
headers DO declare. That guard is what stops it reporting `memcpy`. It was
defeated by a pattern detail: `PROTOTYPE` matched `return SSL_get_cipher_name(p);`
because `return` sits where a return type would, and the call's `)` is followed
by `;`. Three such lines made `SSL_*` a "known namespace" out of nothing but call
sites, and every other OpenSSL call in the file then looked hallucinated.

MEASURED over `paper_data/corpus1k` (1,000 repositories) before the repair:
**23 findings in 4 repositories, all of this class** — OpenSSL in
eventmachine (10), Windows phlib and a vendored libcxxabi in
lucasg/Dependencies (10), Mach `thread_*` in go-delve (2), libtorch in
detectron2 (1).

The shape is taken from `eventmachine/ext/ssl.cpp`, which is where it was found.
