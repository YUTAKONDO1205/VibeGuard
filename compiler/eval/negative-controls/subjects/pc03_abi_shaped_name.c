/* PC-03: an evasion probe, not a control.
 *
 * The other two positive controls inject symbols with ordinary names. This one
 * asks the question those cannot: what happens when the injected symbol is
 * *named* like something the C++ ABI requires the compiler to emit?
 *
 * `lib/origins.mjs` rule R3.abi-entity explains a name by its shape -- `_ZTV` is
 * a virtual table whether or not this build contains one -- and that rule is not
 * a shortcut. It is what lets the baseline generalise to classes nobody had
 * written when the rules were written, and removing it would put every vtable in
 * every future C++ object back into the report. But a shape rule accepts any
 * name of that shape, including one an attacker chose.
 *
 * So this file injects `_ZTV12pc03_Laundry` -- the mangled name of a vtable for
 * a class that does not exist -- as a *function* in an executable section, with
 * a call out of the object.
 *
 * THIS FILE HAS NO EXPECTED VERDICT. It is recorded as a probe: whatever the
 * detector does with it is the measurement, and if it comes out clean that is a
 * false negative to write down, not a fixture to adjust. Filing it as a control
 * with an expectation would mean deciding the answer before running it.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

__asm__(
    ".section .text.pc03_laundered,\"ax\",@progbits\n"
    ".globl _ZTV12pc03_Laundry\n"
    ".type _ZTV12pc03_Laundry,@function\n"
    ".balign 16\n"
    "_ZTV12pc03_Laundry:\n"
    "  pushq %rbp\n"
    "  movq  %rsp, %rbp\n"
    "  xorl  %edi, %edi\n"
    "  movl  $1, %esi\n"
    "  call  dlopen@PLT\n"
    "  popq  %rbp\n"
    "  retq\n"
    ".size _ZTV12pc03_Laundry,.-_ZTV12pc03_Laundry\n"
    ".section .init_array,\"aw\",@init_array\n"
    ".balign 8\n"
    ".quad _ZTV12pc03_Laundry\n"
    ".text\n");

/* The control. interfaces.md §4. */
int pc03_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += (unsigned char)*p;
  return n;
}

int pc03_probe_main(const char *text) { return pc03_control_sum(text); }
