# embedded-volatile-declared — VG-RTOS-003 negative case (correct code)

Byte-for-byte `embedded-volatile-missing` with the one word that makes it
correct: `volatile` on both the declaration in `shared.h` and the definition in
`isr.c`.

Expected: zero findings.

This is the control. Every other negative fixture in this family removes exactly
one guard's worth of information from the positive case; this one removes the
defect itself, so a finding here would mean the rule is not reading the
qualifier at all.
