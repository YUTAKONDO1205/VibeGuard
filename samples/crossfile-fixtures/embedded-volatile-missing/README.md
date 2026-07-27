# embedded-volatile-missing — VG-RTOS-003 positive case

The shape VG-RTOS-002 cannot see, because it is spread over two translation
units:

- `shared.h` declares `extern uint32_t tick_count;` — one declaration, in a
  project header, with a builtin scalar type and no `volatile`.
- `isr.c` includes that header, defines the variable, and writes it from
  `ISR(TIMER1_COMPA_vect)`.
- `main.c` includes the same header and polls the variable from `main`.

Expected: exactly one `VG-RTOS-003` finding, filed on the declaration in
`shared.h` — that is where the fix goes.

`isr.c` deliberately does NOT read `tick_count` outside the handler. If it did,
the single-file rule VG-RTOS-002 would already report it, and this rule hands
that case over rather than reporting it twice.

Deliberately present and deliberately NOT flagged:
- `<stdint.h>` and `<stdio.h>` — angled includes that do not resolve. Only
  QUOTED includes are required to resolve; requiring the system headers would
  make the rule silent on every real firmware file.
- `uint32_t last` in `main` — a local. It is a declaration, but not of the name
  under test, so it is not a shadow.
