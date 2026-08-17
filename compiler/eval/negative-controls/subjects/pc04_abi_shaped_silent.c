/* PC-04: the second half of the evasion probe.
 *
 * PC-03 injects a symbol named like a vtable and calls `dlopen` from it. Three
 * of the four findings stay quiet -- the name explains the symbol, the section
 * that holds it, and the .init_array slot that points at it -- and the one that
 * fires, VG-INTRO-002, fires on the *call*, not on the injection.
 *
 * That leaves an obvious question, and it is the only one worth asking of a
 * detector: what is left if the injected code does not call out of the object?
 *
 * This file answers it. Same ABI-shaped name, same executable section, same
 * .init_array slot, and the body does its work with instructions only -- it
 * writes to a global this translation unit owns, which is what a payload that
 * flips a flag, clears a key or disables a check would do. There is no
 * relocation of a call shape anywhere in it.
 *
 * THIS FILE HAS NO EXPECTED VERDICT. Like PC-03 it is recorded as a probe. A
 * clean result here is a false negative to write down, not a fixture to adjust,
 * and adjusting the R3.abi-entity rule to make it fire is not obviously the
 * right repair: that rule is what keeps every vtable in every future C++ object
 * out of the report, and weakening it trades a measured false negative for an
 * unmeasured pile of false positives. The trade belongs in the record, not in a
 * quiet edit.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

/* The flag a payload would want to reach: an ordinary global of this
 * translation unit, so writing to it needs no call and no external symbol. */
int pc04_guard_enabled = 1;

__asm__(
    ".section .text.pc04_silent,\"ax\",@progbits\n"
    ".globl _ZTV13pc04_Silencer\n"
    ".type _ZTV13pc04_Silencer,@function\n"
    ".balign 16\n"
    "_ZTV13pc04_Silencer:\n"
    "  movl  $0, pc04_guard_enabled(%rip)\n"
    "  retq\n"
    ".size _ZTV13pc04_Silencer,.-_ZTV13pc04_Silencer\n"
    ".section .init_array,\"aw\",@init_array\n"
    ".balign 8\n"
    ".quad _ZTV13pc04_Silencer\n"
    ".text\n");

/* The control. interfaces.md §4. */
int pc04_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += (unsigned char)*p;
  return n;
}

int pc04_probe_main(const char *text) {
  return pc04_guard_enabled ? pc04_control_sum(text) : 0;
}
