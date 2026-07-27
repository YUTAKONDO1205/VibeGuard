# embedded-hallucinated — VG-AISC-002 positive case

`sdk/cxd56_gpio.h` declares four members of the `cxd56_gpio_*` family, so the
project can demonstrably see that API surface. `main.c` calls
`cxd56_gpio_toggle`, which is declared nowhere — no prototype, no macro, no
typedef, no definition in the project.

Expected: exactly one `VG-AISC-002` finding on `main.c`.

Deliberately present and deliberately NOT flagged:
- `printf` — from an unresolved `<stdio.h>`. No project header declares a
  `printf_*` family, so `printf` never belongs to a known namespace.
- `LED_PIN` — a macro, and not in call position anyway.
