// NC-01: template instantiation, on its own.
//
// the design plan section 23.1 requires the Negative Controls to be normal compiler output. This
// file isolates one kind of it: names the compiler generates by instantiating a
// template. Nothing here is virtual, nothing throws, and no lambda appears, so
// a finding on this file cannot be blamed on any of those.
//
// What the compiler is being made to emit:
//
//   * a class template instantiated at four types  -> _ZN...I...E... bodies
//     with a template-argument bracket in the mangled name
//   * a function template instantiated at three types
//   * a recursive function template, so the instantiation set is deeper than
//     one level and includes bodies no line of this file names
//   * a class template with a non-type parameter, whose mangled name carries
//     an integer literal rather than a type
//
// `noinline` is on the instantiated bodies for a measured reason: without it,
// -O2 inlines every one of them into the control and the object contains no
// template instantiation at all, so the fixture passes while exercising
// nothing. The fixture has to still contain what it claims to test at both
// optimisation levels.
//
// No standard-library header is included. <vector> alone drags in several
// hundred names from namespace std, which the origin rules explain by the
// reserved-namespace rule rather than the template rule -- and this file exists
// to exercise the template rule.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

#define NC_NOINLINE __attribute__((noinline))

namespace nc01 {

struct Pair {
  int a;
  int b;
};

inline Pair operator+(const Pair &x, const Pair &y) {
  return Pair{x.a + y.a, x.b + y.b};
}

template <typename T>
class Accumulator {
public:
  explicit Accumulator(T seed) : total_(seed) {}
  NC_NOINLINE void add(const T &v) { total_ = total_ + v; }
  NC_NOINLINE T total() const { return total_; }

private:
  T total_;
};

template <typename T>
NC_NOINLINE T twice(T v) {
  return v + v;
}

// A recursive function template: instantiating depth<4> instantiates depth<3>,
// depth<2>, depth<1> and depth<0> as well, none of which this file writes out.
template <int N>
NC_NOINLINE int depth(int seed) {
  return seed + depth<N - 1>(seed + N);
}

template <>
NC_NOINLINE int depth<0>(int seed) {
  return seed;
}

// A non-type template parameter, so at least one mangled name carries an
// integer literal in its template-argument bracket rather than a type.
template <int Stride>
class Strided {
public:
  NC_NOINLINE int step(int base) const { return base + Stride; }
};

} // namespace nc01

/// The control. compiler/schema/interfaces.md §4: every measurement carries an
/// effect that cannot be optimised away, so that a run in which everything came
/// out zero is recognisable as a broken run rather than read as a clean result.
extern "C" int nc01_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int nc01_template_main(const char *text) {
  using namespace nc01;

  Accumulator<int> ints(1);
  Accumulator<long> longs(2);
  Accumulator<double> doubles(0.5);
  Accumulator<Pair> pairs(Pair{1, 2});

  for (const char *p = text; *p; ++p) {
    ints.add(static_cast<unsigned char>(*p));
    longs.add(static_cast<unsigned char>(*p));
    doubles.add(0.25);
    pairs.add(Pair{1, 1});
  }

  int total = ints.total();
  total += static_cast<int>(longs.total());
  total += static_cast<int>(doubles.total());
  total += pairs.total().a + pairs.total().b;

  total += twice<int>(3);
  total += static_cast<int>(twice<double>(1.5));
  total += twice<long>(4L) != 0 ? 1 : 0;

  total += depth<4>(1);

  Strided<8> s8;
  Strided<16> s16;
  total += s8.step(total) + s16.step(total);

  return total + nc01_control_sum(text);
}
