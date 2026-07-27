# embedded-volatile-typedef — VG-RTOS-003 negative case (qualifier behind a typedef)

The positive case with one change: the type is `reg_t`, and `regs.h` defines it
as `typedef volatile uint32_t reg_t;`. The code is CORRECT — `tick_count` is
volatile — and the declaration line that says so contains no `volatile` token.

Expected: zero findings.

This is why the rule's reportable type set is a closed list of builtin scalars
rather than "any identifier in type position". A declaration whose type this
analysis cannot resolve is not an unqualified declaration, it is an unknown one,
and the rule treats unknown as silence.

The typedef is in a SEPARATE header on purpose. The rule also scans a short
window of text before a declaration for a qualifier on a preceding line, so a
typedef sitting immediately above the `extern` would have silenced this fixture
through that guard instead — and the fixture would then prove nothing about the
type set it exists to test.
