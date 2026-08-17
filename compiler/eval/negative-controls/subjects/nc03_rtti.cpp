// NC-03: run-time type information, on its own.
//
// NC-02 makes the compiler emit a vtable, which drags typeinfo along with it
// because the ABI puts a typeinfo pointer in the vtable's -1 slot. This file
// isolates the other half: RTTI that is *used*, which is what pulls the runtime
// entry points in.
//
// What the compiler is being made to emit:
//
//   * typeid on a polymorphic reference   -> a load of the vtable's typeinfo
//                                            pointer, and a reference to
//                                            std::type_info's own vtable
//   * type_info::name(), ==, before()     -> calls into namespace std
//   * dynamic_cast, downward              -> __dynamic_cast
//   * dynamic_cast, cross-cast between
//     two sibling bases                   -> __dynamic_cast with a non-trivial
//                                            hint argument
//   * dynamic_cast to a reference, which
//     throws on failure                   -> __cxa_bad_cast, and with it the
//                                            personality routine and the
//                                            unwind tables
//   * typeid on a type rather than an
//     expression                          -> a static _ZTI reference with no
//                                            vtable load
//
// <typeinfo> is the one header included, and it is unavoidable: typeid's result
// type is std::type_info and the language requires the header to be visible.
// Its cost is a handful of names in namespace std, which the reserved-namespace
// rule explains -- not the RTTI rules this file is testing, so a finding here
// still points at the right place.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

#include <typeinfo>

namespace nc03 {

class Base {
public:
  virtual ~Base() = default;
  virtual int kind() const { return 1; }
};

class Left : public Base {
public:
  int kind() const override { return 2; }
  virtual int left() const { return 20; }
};

class Right : public Base {
public:
  int kind() const override { return 3; }
  virtual int right() const { return 30; }
};

// Two bases on one object, so that a cross-cast is a cast the compiler cannot
// resolve statically and has to hand to __dynamic_cast.
class Both final : public Left, public Right {
public:
  int left() const override { return 21; }
  int right() const override { return 31; }
};

} // namespace nc03

/// The control. interfaces.md §4.
extern "C" int nc03_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int nc03_rtti_main(const char *text) {
  nc03::Both both;

  // typeid on an expression of polymorphic type: reads the typeinfo pointer out
  // of the object's vtable at run time.
  const nc03::Left &as_left = both;
  const std::type_info &ti = typeid(as_left);
  const char *name = ti.name();

  int total = nc03_control_sum(name);

  // typeid on a type: a static reference to _ZTIN4nc033BothE, no vtable load.
  total += (ti == typeid(nc03::Both)) ? 100 : 0;
  total += ti.before(typeid(nc03::Base)) ? 7 : 0;

  // dynamic_cast downward: __dynamic_cast with a public-base hint.
  const nc03::Base *base = &as_left;
  // `kind` is inherited along both paths, so it has to be named through one of
  // them; `left()` belongs to one base only and needs no qualification.
  if (const nc03::Both *down = dynamic_cast<const nc03::Both *>(base))
    total += down->left() + down->Left::kind();

  // dynamic_cast across: Left -> Right on the same object. Not resolvable
  // statically; this is the shape __dynamic_cast exists for.
  if (const nc03::Right *side = dynamic_cast<const nc03::Right *>(&as_left))
    total += side->right();

  // dynamic_cast to a reference: throws std::bad_cast on failure, so this is
  // what pulls __cxa_bad_cast, the personality routine and the unwind tables in.
  try {
    const nc03::Right &r = dynamic_cast<const nc03::Right &>(
        static_cast<const nc03::Base &>(as_left));
    total += r.right();
  } catch (const std::bad_cast &) {
    total += 1;
  }

  return total + nc03_control_sum(text);
}
