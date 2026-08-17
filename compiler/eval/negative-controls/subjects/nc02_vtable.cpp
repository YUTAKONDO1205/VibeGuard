// NC-02: virtual dispatch, on its own.
//
// Isolates the vtable and the entities the Itanium ABI attaches to it. No
// template is written out, no lambda appears, no typeid or dynamic_cast is
// used, and nothing throws.
//
// What the compiler is being made to emit:
//
//   * a vtable per polymorphic class                 -> _ZTV...
//   * the typeinfo the vtable's -1 slot points at    -> _ZTI..., _ZTS...
//     (unavoidable: a vtable cannot be emitted without one. RTTI *use* --
//     typeid and dynamic_cast, which call into the runtime -- is NC-03's job,
//     and this file does neither.)
//   * a pure virtual, so the vtable slot for it is
//     __cxa_pure_virtual                             -> a runtime entry point
//   * virtual destructors, both the complete and the
//     deleting form                                  -> D0/D1/D2 bodies
//   * a virtual base, so a VTT and a construction
//     vtable are emitted                             -> _ZTT..., _ZTC...
//
// The objects are constructed through a volatile pointer and dispatched through
// a base reference so that -O2 cannot devirtualise the calls, fold the classes
// away and leave an object containing no vtable -- which would make the fixture
// pass while testing nothing.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

namespace nc02 {

class Shape {
public:
  virtual ~Shape() = default;
  virtual int area() const = 0;             // pure: __cxa_pure_virtual slot
  virtual int perimeter() const { return 0; }
};

class Sized : public virtual Shape {        // virtual base: VTT, construction vtable
public:
  int area() const override { return side_ * side_; }
  int perimeter() const override { return 4 * side_; }
  virtual int side() const { return side_; }

protected:
  int side_ = 3;
};

class Square final : public Sized {
public:
  int perimeter() const override { return 4 * side() + 1; }
};

class Rect final : public Sized {
public:
  int area() const override { return side() * (side() + 1); }
};

} // namespace nc02

/// The control. interfaces.md §4.
extern "C" int nc02_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int nc02_vtable_main(const char *text) {
  nc02::Square sq;
  nc02::Rect rc;

  // Dispatch through a base reference the optimiser cannot see through: the
  // selection depends on a value it does not know at compile time.
  volatile int pick = static_cast<int>(*text) & 1;
  const nc02::Shape &chosen = pick ? static_cast<const nc02::Shape &>(sq)
                                   : static_cast<const nc02::Shape &>(rc);

  int total = chosen.area() + chosen.perimeter();

  // A virtual call through a pointer that leaves the function's view, so the
  // vtable load is a real load.
  nc02::Shape *volatile escaped = &sq;
  total += escaped->area();

  // Virtual destruction through a base pointer: the deleting destructor slot.
  nc02::Shape *owned = new nc02::Square();
  total += owned->perimeter();
  delete owned;

  return total + nc02_control_sum(text);
}
