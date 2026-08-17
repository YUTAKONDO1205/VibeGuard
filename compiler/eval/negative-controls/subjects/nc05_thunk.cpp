// NC-05: thunks, on their own.
//
// A thunk is a function body the compiler writes that adjusts `this` (or the
// return value) and tail-calls the real override. Nobody writes one; nobody can
// grep the source for it; and there are three different kinds with three
// different mangled prefixes. All three are here.
//
// What the compiler is being made to emit:
//
//   * a non-virtual thunk        -> _ZThn<offset>_...   from an override
//     reached through the second base of a multiple-inheritance derived class,
//     where `this` has to be shifted by a constant.
//   * a virtual thunk            -> _ZTv0_n<offset>_... from an override
//     reached through a *virtual* base, where the shift is not a constant and
//     has to be read out of the vtable.
//   * a covariant-return thunk   -> _ZTch..._h..._...   from an override whose
//     return type is a derived class reached through a second base, so the
//     returned pointer needs adjusting as well as `this`.
//
// Getting all three out of one file needs three separate hierarchies; there is
// no single shape that produces them all. The classes are therefore grouped by
// which thunk they exist to produce, and each group is commented with it.
//
// Everything is dispatched through a base reference chosen by a volatile value,
// so -O2 cannot devirtualise and delete the thunks it was meant to keep.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

namespace nc05 {

// --- group 1: non-virtual thunk (_ZThn) ------------------------------------
// Two independent polymorphic bases. `Both` overrides a virtual belonging to
// the *second* base, whose subobject sits at a non-zero offset, so the entry in
// Second's vtable cannot point at the override directly.

class First {
public:
  virtual ~First() = default;
  virtual int first() const { return 1; }
};

class Second {
public:
  virtual ~Second() = default;
  virtual int second() const { return 2; }
  virtual int also() const { return 3; }
};

class Both final : public First, public Second {
public:
  int first() const override { return 11; }
  int second() const override { return 12; }   // reached via a _ZThn thunk
  int also() const override { return 13; }     // and this one too
};

// --- group 2: virtual thunk (_ZTv) -----------------------------------------
// A virtual base inherited along two paths. The offset from a VBase* to the
// most-derived object is not known at compile time, so the adjustment is read
// from the vtable and the thunk carries the _ZTv prefix.

class VBase {
public:
  virtual ~VBase() = default;
  virtual int value() const { return 100; }
};

class VLeft : public virtual VBase {
public:
  int value() const override { return 101; }
};

class VRight : public virtual VBase {
public:
  virtual int right() const { return 102; }
};

class VDiamond final : public VLeft, public VRight {
public:
  int value() const override { return 103; }   // reached via a _ZTv thunk
  int right() const override { return 104; }
};

// --- group 3: covariant-return thunk (_ZTc) --------------------------------
// `clone` returns a pointer to the class itself. In `CoDerived` the return type
// is CoDerived*, which is a *different address* from the CoBase* the base's
// signature promises, because CoDerived reaches CoBase through a second base.
// The compiler emits a thunk that adjusts the returned pointer.

class CoBase {
public:
  virtual ~CoBase() = default;
  virtual CoBase *clone() const { return nullptr; }
};

class CoFiller {
public:
  virtual ~CoFiller() = default;
  virtual int filler() const { return 5; }
};

class CoDerived final : public CoFiller, public CoBase {
public:
  CoDerived *clone() const override { return nullptr; }  // covariant return
  int filler() const override { return 6; }
};

} // namespace nc05

/// The control. interfaces.md §4.
extern "C" int nc05_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += static_cast<unsigned char>(*p);
  return n;
}

extern "C" int nc05_thunk_main(const char *text) {
  int total = nc05_control_sum(text);
  volatile int pick = static_cast<int>(*text) & 1;

  // Group 1, dispatched through the second base: the thunk is what runs.
  nc05::Both both;
  const nc05::Second &as_second = both;
  const nc05::First &as_first = both;
  total += as_second.second() + as_second.also() + as_first.first();

  // Group 2, dispatched through the virtual base.
  nc05::VDiamond diamond;
  nc05::VLeft left;
  const nc05::VBase &as_vbase = pick ? static_cast<const nc05::VBase &>(diamond)
                                     : static_cast<const nc05::VBase &>(left);
  total += as_vbase.value();
  const nc05::VRight &as_vright = diamond;
  total += as_vright.right();

  // Group 3, called through the base signature so the covariant adjustment runs.
  nc05::CoDerived derived;
  const nc05::CoBase &as_cobase = derived;
  total += (as_cobase.clone() == nullptr) ? 1 : 0;
  const nc05::CoFiller &as_filler = derived;
  total += as_filler.filler();

  // Escape one object per hierarchy, so the optimiser cannot prove any of them
  // is local, delete the vtable stores, and take the thunks with it.
  //
  // Measured: without the two virtual-base escapes below, clang-18 -O2
  // devirtualises the whole VDiamond hierarchy, discards its vtables, and the
  // object contains zero _ZTv thunks -- the fixture then passes while
  // exercising nothing. Group 1 survived on its own because `both` was already
  // escaping; group 2 did not.
  const nc05::Second *volatile escaped_second = &both;
  total += escaped_second->second();

  const nc05::VBase *volatile escaped_vbase = &diamond;
  total += escaped_vbase->value();

  const nc05::VRight *volatile escaped_vright = &diamond;
  total += escaped_vright->right();

  const nc05::CoBase *volatile escaped_cobase = &derived;
  total += (escaped_cobase->clone() == nullptr) ? 2 : 0;

  return total;
}
