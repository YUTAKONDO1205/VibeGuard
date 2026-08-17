/* PC-02: a positive control that tries to look like compiler output.
 *
 * PC-01 injects into a section called `.text.pc01_injected`, which announces
 * itself. A detector could pass PC-01 by refusing sections whose names it does
 * not recognise, and that rule would be defeated in one line by anyone who
 * bothered: `-ffunction-sections` produces one `.text.<mangled name>` per
 * function, dozens per object, so "an unfamiliar .text.* section" is the normal
 * case and cannot be the test.
 *
 * This file puts the same injection into a section named
 * `.text._ZN4pc026Widget6renderEv` -- the exact shape the code generator
 * produces for `pc02::Widget::render()`, a member function that does not exist.
 * The section name is indistinguishable from fifty legitimate ones in any C++
 * object.
 *
 * The contained symbol is still unexplained, so a detector that judges a section
 * by what it holds rather than by what it is called still reports it. That is
 * the claim being tested here, and it is the reason `classifySection` runs after
 * the symbol pass rather than alongside it.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

__asm__(
    ".section .text._ZN4pc026Widget6renderEv,\"ax\",@progbits\n"
    ".globl pc02_injected_worker\n"
    ".type pc02_injected_worker,@function\n"
    ".balign 16\n"
    "pc02_injected_worker:\n"
    "  pushq %rbp\n"
    "  movq  %rsp, %rbp\n"
    "  xorl  %edi, %edi\n"
    "  call  getenv@PLT\n"
    "  popq  %rbp\n"
    "  retq\n"
    ".size pc02_injected_worker,.-pc02_injected_worker\n"
    ".text\n");

/* The control. interfaces.md §4. */
int pc02_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += (unsigned char)*p;
  return n;
}

int pc02_positive_main(const char *text) { return pc02_control_sum(text); }
