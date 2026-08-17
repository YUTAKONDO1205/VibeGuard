// NC-06: static initialisers, on their own.
//
// This is the negative control that matters most, because VG-INTRO-003 is the
// critical finding: an .init_array slot runs before main. A detector that
// cannot tell an honest dynamic initialiser from an injected one will either
// report every C++ file with a global object (useless) or report none of them
// (blind).
//
// What the compiler is being made to emit:
//
//   * a namespace-scope object with a non-constant initialiser
//                                  -> __cxx_global_var_init, and an
//                                     _GLOBAL__sub_I_<file> entry in .init_array
//   * several of them, so the entry runs more than one initialiser
//   * an object with a non-trivial destructor
//                                  -> __cxa_atexit, and a reference to
//                                     __dso_handle
//   * a function-local static with a non-constant initialiser
//                                  -> a guard variable (_ZGV...) and
//                                     __cxa_guard_acquire / __cxa_guard_release
//   * an array of objects with a non-trivial constructor
//                                  -> an array-construction loop, and on
//                                     failure an array destructor helper
//   * a C-style constructor attribute
//                                  -> a *second, independent* .init_array slot
//                                     that is not _GLOBAL__sub_I_ at all
//   * a destructor attribute       -> a .fini_array slot
//
// The last two are the sharp edge. `__attribute__((constructor))` puts a plain,
// source-named function into .init_array with no ABI-shaped name standing
// behind it -- which is structurally the same thing the positive control
// injects. The difference is that this one *is* in the front end's output for
// this compilation and the injected one is not, so this fixture is what shows
// the measured half of the baseline doing work that no name-shape rule could do.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

namespace nc06 {

// A type with a non-trivial constructor and a non-trivial destructor, so the
// compiler needs both an initialiser and an atexit registration.
class Counter {
public:
  explicit Counter(int seed) : value_(seed) { value_ += seed % 7; }
  ~Counter() { value_ = 0; }
  int value() const { return value_; }

private:
  int value_;
};

// Not constexpr, so the initialiser has to run at start-up rather than being
// folded into .data.
__attribute__((noinline)) static int seed_from_nowhere(int base) {
  volatile int v = base;
  return v * 3 + 1;
}

} // namespace nc06

// --- namespace-scope objects needing dynamic initialisation -----------------
static nc06::Counter g_first(nc06::seed_from_nowhere(1));
static nc06::Counter g_second(nc06::seed_from_nowhere(2));

// An array of them: array construction, and an array destructor helper.
static nc06::Counter g_array[3] = {
    nc06::Counter(nc06::seed_from_nowhere(3)),
    nc06::Counter(nc06::seed_from_nowhere(4)),
    nc06::Counter(nc06::seed_from_nowhere(5)),
};

// A pointer initialised from a non-constant expression: dynamic initialisation
// without a destructor, so this one needs no __cxa_atexit.
static int g_dynamic_int = nc06::seed_from_nowhere(6);

// --- a function-local static: guard variable + __cxa_guard_acquire ----------
__attribute__((noinline)) static const nc06::Counter &lazy() {
  static const nc06::Counter value(nc06::seed_from_nowhere(7));
  return value;
}

// --- the C-style attributes: .init_array and .fini_array without an ABI name -
static int g_ctor_ran;

__attribute__((constructor)) static void nc06_early(void) {
  g_ctor_ran = nc06::seed_from_nowhere(8);
}

// A *prioritised* constructor. This one does not land in `.init_array`: the
// toolchain gives it a section of its own, `.init_array.65535`, which the
// object reader's INIT_SECTIONS set does not list. It is here so that the
// corpus records what the shape produces rather than leaving it untried.
__attribute__((constructor(65535))) static void nc06_early_prioritised(void) {
  g_ctor_ran += 1;
}

__attribute__((destructor)) static void nc06_late(void) {
  g_ctor_ran = 0;
}

/// The control. interfaces.md §4.
extern "C" int nc06_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int nc06_static_init_main(const char *text) {
  int total = g_first.value() + g_second.value() + g_dynamic_int + g_ctor_ran;
  for (const auto &c : g_array)
    total += c.value();
  total += lazy().value();
  return total + nc06_control_sum(text);
}
