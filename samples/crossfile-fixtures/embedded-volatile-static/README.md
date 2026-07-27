# embedded-volatile-static — VG-RTOS-003 negative case (`static` veto)

`isr.c`, `main.c`, and `shared.h` are the positive case verbatim: the finding
would fire on them alone. `logger.c` is the only difference — it declares its own
`static uint32_t tick_count`, a legal, unrelated, file-local object that happens
to share the name.

Expected: zero findings.

**This is a deliberate false negative, and it is the price of the guard.** A
lexical scan cannot prove that `logger.c`'s `tick_count` is a different object
from `shared.h`'s, so a `static` declaration of the name ANYWHERE in the project
silences the rule. Reporting anyway would mean accusing a variable on evidence
gathered from a different variable, which is the failure mode that makes a
design-smell rule get switched off.

`logger.c` is `static` and nothing else: it is not a second definition (the
definition count excludes statics on purpose), so the `static` guard is the only
thing standing between this fixture and a finding. If that guard is removed, this
fixture starts reporting — which is what its test asserts against.
