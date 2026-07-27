# embedded-volatile-two-decls — VG-RTOS-003 negative case (ambiguous declaration)

Two project headers declare `uint32_t tick_count`: `shared.h`, which `isr.c`
includes, and `legacy/board.h`, which `main.c` includes. Everything else is the
positive case.

Expected: zero findings.

Which declaration a translation unit actually sees is decided by the include
path, and the include path is not available to a source scan — the same reason
`resolveSpecifier` refuses an ambiguous suffix match rather than picking a
candidate. So the rule requires EXACTLY ONE declaration in a project header and
says nothing when there are two.

That also means the rule cannot report the arguably worse bug on display here
(two headers describing one global), and it does not pretend to: silence is the
answer to ambiguity, not a report hedged with "probably".
