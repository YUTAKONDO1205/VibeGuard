// NC-04: lambdas, on their own.
//
// A lambda is a class the source never names, with a call operator the source
// never declares, and clang mangles it into one of two encodings depending on
// where the closure lives. Both are here, because a rule that only knew one of
// them would pass this fixture in one build and report the other.
//
// What the compiler is being made to emit:
//
//   * a capture-by-value closure              -> _ZZ...ENK3$_0clE... or the
//                                                Ul...E_ encoding
//   * a capture-by-reference closure
//   * a mutable closure with state
//   * a generic lambda (auto parameter)       -> the call operator is itself a
//                                                template, so the closure type
//                                                carries a template-argument
//                                                bracket as well
//   * a captureless lambda converted to a
//     function pointer                        -> the ABI's static invoker
//                                                (`__invoke`) and the
//                                                conversion operator
//   * a lambda at namespace scope, in the
//     initialiser of a global                 -> a closure type outside any
//                                                function's local scope
//   * a lambda nested inside another lambda   -> a closure type whose mangled
//                                                name contains another one
//
// Every closure is called through something the optimiser cannot fold: a
// volatile selector, or a function pointer that escapes. Otherwise -O2 inlines
// all of them and the object contains no closure type at all, and the fixture
// tests nothing while reporting green.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

#define NC_NOINLINE __attribute__((noinline))

namespace nc04 {

// A lambda at namespace scope: the closure type is not local to any function.
static const auto kScale = [](int v) NC_NOINLINE { return v * 3; };

// A minimal callable-holder, so that a closure has to be stored and called
// indirectly without pulling std::function (and several hundred std names) in.
template <typename F>
NC_NOINLINE int apply_twice(F f, int seed) {
  return f(seed) + f(seed + 1);
}

} // namespace nc04

/// The control. interfaces.md §4.
extern "C" int nc04_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int nc04_lambda_main(const char *text) {
  int total = nc04_control_sum(text);

  // 1. capture by value.
  const int seed = total;
  auto by_value = [seed](int v) NC_NOINLINE { return v + seed; };

  // 2. capture by reference.
  int running = 0;
  auto by_ref = [&running](int v) NC_NOINLINE {
    running += v;
    return running;
  };

  // 3. mutable, with state that survives between calls.
  // The attribute goes before `mutable` here: clang-18 in C++17 mode wants the
  // lambda body immediately after `mutable`, and rejects a GNU attribute
  // between the two. Measured, not guessed.
  auto counting = [count = 0](int v) NC_NOINLINE mutable {
    count += v;
    return count;
  };

  // 4. generic: the call operator is a template, instantiated at two types.
  auto generic = [](auto v) NC_NOINLINE { return static_cast<int>(v + v); };

  // 5. captureless, converted to a plain function pointer. The conversion is
  //    what makes the ABI emit the static invoker.
  int (*as_fn)(int) = +[](int v) NC_NOINLINE { return v ^ 0x5a; };

  // 6. nested: a closure type defined inside another closure's body.
  auto outer = [](int v) NC_NOINLINE {
    auto inner = [](int w) NC_NOINLINE { return w - 1; };
    return inner(v) + inner(v + 2);
  };

  volatile int pick = static_cast<int>(*text) & 3;

  total += nc04::apply_twice(by_value, pick);
  total += nc04::apply_twice(by_ref, pick + 1);
  total += nc04::apply_twice(counting, pick + 2);
  total += nc04::apply_twice(generic, pick + 3);
  total += generic(1.5);
  total += as_fn(pick);
  total += outer(pick);
  total += nc04::kScale(pick);

  // The function pointer escapes, so the invoker cannot be folded away.
  int (*volatile escaped)(int) = as_fn;
  total += escaped(total & 0xff);

  return total;
}
