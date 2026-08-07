/* The positive fixture: a translation unit that carries an introduction the
 * front end never declared.
 *
 * The mechanism is module-level inline assembly. Text handed to the assembler
 * this way never enters LLVM's IR symbol table -- there is no `define` and no
 * `@global` for it -- so the symbol, the section and the .init_array entry it
 * creates exist in the object file and nowhere in the compiler's own model of
 * the translation unit. That is exactly the shape a pass plugin or an assembler
 * wrapper would use to add something to a build, and it is why the detector
 * cannot be an IR-only check.
 *
 * Four things are injected, one per finding:
 *
 *   VG-INTRO-001  a defined symbol, `intro_injected_thunk`, that no source
 *                 entity accounts for
 *   VG-INTRO-002  a call from that symbol into `dlopen`, which the policy's
 *                 approved external calls do not list
 *   VG-INTRO-003  an .init_array slot pointing at it -- a static initialiser
 *                 that the compiler did not emit and that therefore has no
 *                 _GLOBAL__sub_I_ entry standing behind it
 *   VG-INTRO-004  the executable section `.text.intro_injected` it lives in
 *
 * The ordinary C below it is not decoration. Without a real function and a real
 * initialiser present, "the detector found something" would be indistinguishable
 * from "the detector flagged the whole file", and the fixture would prove
 * nothing about precision.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

#include <stddef.h>

/* The injection. x86-64 System V: the call is written as a PLT-relative call so
 * that the object relocates against dlopen the way a compiler-emitted call
 * would, which is the point -- an object-level detector must not be able to
 * tell this apart by looking at the relocation type. */
__asm__(
    ".section .text.intro_injected,\"ax\",@progbits\n"
    ".globl intro_injected_thunk\n"
    ".type intro_injected_thunk,@function\n"
    ".balign 16\n"
    "intro_injected_thunk:\n"
    "  pushq %rbp\n"
    "  movq  %rsp, %rbp\n"
    "  xorl  %edi, %edi\n"
    "  movl  $1, %esi\n"
    "  call  dlopen@PLT\n"
    "  popq  %rbp\n"
    "  retq\n"
    ".size intro_injected_thunk,.-intro_injected_thunk\n"
    ".section .init_array,\"aw\",@init_array\n"
    ".balign 8\n"
    ".quad intro_injected_thunk\n"
    ".text\n");

/* --- the ordinary part of the translation unit ---------------------------- */

/* The control. Section 4 of compiler/schema/interfaces.md. */
int intro_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += (unsigned char)*p;
  return n;
}

/* A legitimate static initialiser, so that the fixture proves the detector
 * separates the injected .init_array slot from an honest one rather than
 * flagging .init_array wholesale.
 *
 * `intro_boot_text` is a mutable global rather than a string literal for a
 * measured reason: with a literal, -O2 constant-folds the whole constructor
 * away, the .init_array entry disappears, and the fixture quietly stops
 * containing the honest initialiser it exists to contrast against. Measured
 * with clang-18 -O2 -- the first version of this file had exactly that hole. */
const char *intro_boot_text = "boot";
static int boot_total;

__attribute__((constructor)) static void intro_positive_boot(void) {
  boot_total = intro_control_sum(intro_boot_text);
}

int intro_positive_main(const char *text) {
  return boot_total + intro_control_sum(text);
}
