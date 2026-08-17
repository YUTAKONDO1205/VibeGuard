/* PC-01: the positive control for the whole corpus.
 *
 * WHY THIS FILE DECIDES WHETHER THE OTHER SEVEN MEAN ANYTHING. Seven negative
 * controls reporting "Unexplained = 0" is exactly what a detector that has been
 * switched off reports, and exactly what a detector whose thresholds were tuned
 * until the fixtures went quiet reports. The two are indistinguishable from the
 * negative controls alone. This file is the distinguisher: it is compiled with
 * the same compiler, the same flags and the same runner as whichever negative
 * control it is paired with, and it must produce findings. A run in which the
 * negative controls are clean and this file is *also* clean is a broken run, not
 * a good result, and the runner treats it as a failure.
 *
 * THE MECHANISM. Module-level inline assembly. Text handed to the assembler this
 * way never enters LLVM's IR symbol table -- there is no `define` and no
 * `@global` for it -- so the symbol, the section and the .init_array slot it
 * creates exist in the object file and nowhere in the compiler's own model of
 * the translation unit. That is the shape a pass plugin or an assembler wrapper
 * would use to add something to a build, and it is why the check cannot be an
 * IR-only one.
 *
 * Four injections, one per finding:
 *
 *   VG-INTRO-001  a defined symbol, `pc01_injected_thunk`, that no source
 *                 entity accounts for
 *   VG-INTRO-002  a call from it into `dlopen`, which no permitted origin
 *                 explains
 *   VG-INTRO-003  an .init_array slot pointing at it -- a static initialiser
 *                 the compiler did not emit, with no _GLOBAL__sub_I_ standing
 *                 behind it
 *   VG-INTRO-004  the executable section `.text.pc01_injected` it lives in
 *
 * The ordinary C below the injection is not decoration. Without a real function
 * and a real, honest initialiser in the same object, "the detector found
 * something" would be indistinguishable from "the detector flagged the whole
 * file", and this control would prove nothing about precision.
 *
 * This file is compiled as C++ in some configurations (with `-x c++`), so it
 * stays inside the subset both languages read the same way.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

/* The injection. x86-64 System V: the call is written as a PLT-relative call so
 * that the object relocates against dlopen the way a compiler-emitted call
 * would. An object-level detector must not be able to tell this apart by the
 * relocation type. */
__asm__(
    ".section .text.pc01_injected,\"ax\",@progbits\n"
    ".globl pc01_injected_thunk\n"
    ".type pc01_injected_thunk,@function\n"
    ".balign 16\n"
    "pc01_injected_thunk:\n"
    "  pushq %rbp\n"
    "  movq  %rsp, %rbp\n"
    "  xorl  %edi, %edi\n"
    "  movl  $1, %esi\n"
    "  call  dlopen@PLT\n"
    "  popq  %rbp\n"
    "  retq\n"
    ".size pc01_injected_thunk,.-pc01_injected_thunk\n"
    ".section .init_array,\"aw\",@init_array\n"
    ".balign 8\n"
    ".quad pc01_injected_thunk\n"
    ".text\n");

/* --- the ordinary part of the translation unit ---------------------------- */

/* The control. interfaces.md §4. */
int pc01_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += (unsigned char)*p;
  return n;
}

/* An honest static initialiser, so this control proves the detector separates
 * the injected .init_array slot from a legitimate one rather than flagging
 * .init_array wholesale.
 *
 * `pc01_boot_text` is a mutable global rather than a string literal for a
 * measured reason: with a literal, -O2 constant-folds the constructor away, the
 * .init_array entry disappears, and the file quietly stops containing the
 * honest initialiser it exists to contrast against. */
const char *pc01_boot_text = "boot";
static int pc01_boot_total;

__attribute__((constructor)) static void pc01_boot(void) {
  pc01_boot_total = pc01_control_sum(pc01_boot_text);
}

int pc01_positive_main(const char *text) {
  return pc01_boot_total + pc01_control_sum(text);
}
