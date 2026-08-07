// The negative control for introduction analysis: a C++ translation unit that
// makes the compiler emit as much of its own machinery as one small file can,
// and nothing else.
//
// Everything in here is *legitimate* compiler output. A detector that has no
// toolchain baseline to subtract will read the vtable, the typeinfo, the
// template instantiations, the lambda's call operator, the thunk and the
// dynamic-initialisation constructor as "things that appeared that the source
// did not ask for", and will accuse the compiler of doing its job. That is the
// failure this file exists to catch, so the contract on it is exact: the
// verdict on this fixture must contain zero Unexplained elements. If one shows
// up, the rules are wrong and the rules get fixed -- this file does not get an
// exception added for it.
//
// The features are listed here so that a later reader can check the fixture
// still exercises them rather than trusting that it once did:
//
//   * a class template, instantiated at two types  -> mangled names carrying
//     template arguments
//   * a virtual base and an override               -> vtable, VTT
//   * two inheritance paths onto one override      -> a covariant/virtual thunk
//   * typeid / dynamic_cast                        -> RTTI: typeinfo, typeinfo
//                                                     name, __dynamic_cast
//   * a lambda, captured and called                -> a closure type and its
//                                                     operator()
//   * a namespace-scope object with a non-constant
//     initialiser                                  -> __cxx_global_var_init and
//                                                     _GLOBAL__sub_I_*
//   * a function-local static                      -> a guard variable and
//                                                     __cxa_guard_acquire
//   * throw / catch                                -> __cxa_throw, the
//                                                     personality routine
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

#include <cstddef>
#include <string>
#include <typeinfo>
#include <vector>

namespace {

// --- a class template, so that instantiation happens twice -----------------
template <typename T>
class Accumulator {
public:
  explicit Accumulator(T seed) : total_(seed) {}
  void add(const T &v) { total_ = total_ + v; }
  const T &total() const { return total_; }

private:
  T total_;
};

// --- virtual inheritance, an override, RTTI --------------------------------
class Shape {
public:
  virtual ~Shape() = default;
  virtual int area() const = 0;
  virtual const char *tag() const { return "shape"; }
};

class Sized : public virtual Shape {
public:
  int area() const override { return side_ * side_; }
  const char *tag() const override { return "sized"; }

protected:
  int side_ = 3;
};

class Square final : public Sized {
public:
  const char *tag() const override { return "square"; }
};

} // namespace

// --- a function-local static: guard variable + __cxa_guard_acquire ---------
static const std::string &table() {
  static const std::string value = "abc";
  return value;
}

// --- a namespace-scope object needing dynamic initialisation ---------------
// This is what produces __cxx_global_var_init and the _GLOBAL__sub_I_ entry in
// .init_array. The negative fixture needs one because the positive fixture
// injects an .init_array entry of its own, and a detector that cannot tell
// those two apart is useless.
static std::vector<int> seeds = {2, 3, 5, 7};

/// The control. Section 4 of compiler/schema/interfaces.md: every measurement
/// carries an effect that cannot be optimised away, so that a run in which
/// everything came out zero is recognisable as a broken run rather than read as
/// a clean result.
extern "C" int intro_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int intro_negative_main(const char *text) {
  Square sq;

  // RTTI, both halves of it: typeid on a polymorphic object reads the vtable's
  // typeinfo pointer, dynamic_cast calls into the runtime.
  const Shape &as_shape = sq;
  const char *name = typeid(as_shape).name();
  const Sized *back = dynamic_cast<const Sized *>(&as_shape);

  Accumulator<int> ints(0);
  Accumulator<std::size_t> sizes(0);

  // A lambda, captured by reference, so the closure type is real rather than
  // folded away.
  auto tally = [&ints, &sizes](const char *p) {
    for (; *p; ++p) {
      ints.add(static_cast<unsigned char>(*p));
      sizes.add(1);
    }
  };
  tally(text);
  tally(name);

  int total = ints.total() + static_cast<int>(sizes.total());
  total += as_shape.area() + (back ? back->area() : 0);
  total += static_cast<int>(table().size());
  for (int s : seeds)
    total += s;

  // Exception machinery, so that the personality routine and the unwind tables
  // are part of what the baseline has to explain.
  try {
    if (total < 0)
      throw std::string("negative");
  } catch (const std::string &e) {
    total += static_cast<int>(e.size());
  }

  return total + intro_control_sum(text);
}
