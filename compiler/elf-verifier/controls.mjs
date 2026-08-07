// Negative and positive controls for the introduction classifier.
//
// The sources are generated rather than tracked, for the same reason
// measurement output is: they are inputs to a measurement, they get compiled
// into machine-specific objects next to themselves, and `compiler/` is a
// published tree. `node controls.mjs --write <dir>` reconstructs them exactly.
//
// Six negative controls, one per compiler-generated construct that a naive
// "something new appeared" detector accuses. Every symbol these produce is a
// correct, expected product of compiling the source next to it; a classifier
// that reports any of them is a classifier nobody will keep switched on.

import { mkdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

export const NEGATIVE_CONTROLS = [
  {
    name: 'template-instantiation',
    file: 'ctl_template.cc',
    flags: ['-O0'],
    why: 'Instantiating a template emits weak definitions that exist in no source file literally.',
    source: `// Negative control: template instantiation.
// Explicit instantiation forces the definitions out of line so the linked image
// really contains them rather than having inlined them away at -O0.
template <typename T>
T combine(T a, T b) {
  return a + b;
}

template <typename T>
struct Box {
  T v;
  T get() const { return v; }
  T twice() const { return combine<T>(v, v); }
};

template int combine<int>(int, int);
template struct Box<int>;
template struct Box<long>;

int main() {
  Box<int> bi{2};
  Box<long> bl{3};
  return static_cast<int>(bi.twice() + bl.twice()) - 10;
}
`,
  },
  {
    name: 'vtable-rtti',
    file: 'ctl_vtable.cc',
    flags: ['-O0'],
    why: 'A polymorphic class emits _ZTV/_ZTI/_ZTS and pulls the ABI type-info bases in from libstdc++.',
    source: `// Negative control: vtable and RTTI.
#include <typeinfo>

struct Shape {
  virtual ~Shape() {}
  virtual int area() const { return 0; }
};

struct Square : Shape {
  int side;
  explicit Square(int s) : side(s) {}
  int area() const override { return side * side; }
};

int main() {
  Shape* p = new Square(3);
  int r = p->area();
  const char* n = typeid(*p).name();
  bool ok = dynamic_cast<Square*>(p) != nullptr;
  delete p;
  return r - 9 + (n[0] ? 0 : 1) + (ok ? 0 : 1);
}
`,
  },
  {
    name: 'lambda',
    file: 'ctl_lambda.cc',
    flags: ['-O0'],
    why: 'Closure types mangle as Ul...E_ and emit operator(), the function-pointer conversion and __invoke.',
    source: `// Negative control: lambda closure types.
template <typename F>
int run(F f, int x) {
  return f(x);
}

int main() {
  int k = 2;
  auto add_k = [k](int x) { return x + k; };
  auto plain = [](int x) { return x * 2; };
  int (*fp)(int) = plain;  // conversion operator + __invoke thunk
  return run(add_k, 3) + fp(1) - 7;
}
`,
  },
  {
    name: 'static-initializer',
    file: 'ctl_staticinit.cc',
    flags: ['-O0'],
    why: 'Namespace-scope dynamic initialisation emits _GLOBAL__sub_I_*, __cxx_global_var_init* and an .init_array slot; a function-local static adds a _ZGV guard.',
    source: `// Negative control: static initialisers and guard variables.
struct Reg {
  int n;
  explicit Reg(int x);
};

int sink = 0;

Reg::Reg(int x) : n(x) { sink += x; }

static Reg g_a(3);
Reg g_b(4);

int& counter() {
  static int c = sink + 1;  // guard variable, non-constant initialiser
  return c;
}

int main() { return sink + counter() - 15; }
`,
  },
  {
    name: 'thunk',
    file: 'ctl_thunk.cc',
    flags: ['-O0'],
    why: 'Multiple inheritance emits non-virtual thunks (_ZThn*), virtual inheritance emits virtual thunks (_ZTv*), a VTT (_ZTT*) and construction vtables (_ZTC*).',
    source: `// Negative control: thunks from multiple and virtual inheritance.
struct A {
  virtual ~A() {}
  virtual int a() { return 1; }
};

struct B {
  virtual ~B() {}
  virtual int b() { return 2; }
};

struct C : A, B {
  int a() override { return 3; }
  int b() override { return 4; }
};

struct V {
  virtual ~V() {}
  virtual int v() { return 1; }
};

struct L : virtual V {
  int v() override { return 2; }
};

struct R : virtual V {
  virtual int r() { return 5; }
};

struct D : L, R {
  int v() override { return 3; }
  int r() override { return 6; }
};

int main() {
  C c;
  A* pa = &c;
  B* pb = &c;
  D d;
  V* pv = &d;
  R* pr = &d;
  return pa->a() + pb->b() + pv->v() + pr->r() - 16;
}
`,
  },
  {
    name: 'sanitizer-address',
    file: 'ctl_asan.cc',
    flags: ['-O0', '-fsanitize=address'],
    why: 'AddressSanitizer adds a module constructor, an .init_array slot, __odr_asan_gen_* globals and a large runtime import surface.',
    source: `// Negative control: -fsanitize=address instrumentation.
int global_buf[16];
int other_global = 5;

int touch(int i) {
  global_buf[i] = i * 2;
  return global_buf[i];
}

int main() { return touch(3) + other_global - 11; }
`,
  },
];

// The positive control's declared source. Nothing is injected here: the marker
// is added to the *object* afterwards, which is the shape of the threat — a
// pass or a post-processing step putting something into an artefact that the
// declared translation unit does not account for.
export const POSITIVE_CONTROL = {
  name: 'injected-symbol',
  file: 'ctl_inject_base.cc',
  flags: ['-O0'],
  source: `// Positive-control base. Ordinary source; the marker is injected into the
// object produced from it, not written here.
int compute(int x) { return x * 3; }

int main() { return compute(2) - 6; }
`,
};

// The injected material, as assembly. Three separate things, because they are
// three separate findings: a symbol nothing declares (VG-INTRO-001), an
// executable section nothing declares (VG-INTRO-004), and a slot in
// `.init_array` that runs code before main (VG-INTRO-003). A detector that
// catches only the first is blind to the two that actually get you executed.
// `.note.GNU-stack` is present because leaving it out makes the linker mark the
// whole image as requiring an executable stack. That is a second, louder change
// to the artefact, and a positive control that alters two things at once cannot
// say which one the detector reacted to.
export const INJECTION_ASM = `        .section .note.GNU-stack,"",@progbits

        .text
        .globl  __unaccounted_marker_probe
        .type   __unaccounted_marker_probe, @function
__unaccounted_marker_probe:
        xorl    %eax, %eax
        ret
        .size   __unaccounted_marker_probe, .-__unaccounted_marker_probe

        .section .injected_exec,"ax",@progbits
        .globl  __unaccounted_exec_probe
        .type   __unaccounted_exec_probe, @function
__unaccounted_exec_probe:
        xorl    %eax, %eax
        ret
        .size   __unaccounted_exec_probe, .-__unaccounted_exec_probe

        .text
        .globl  __unaccounted_init_probe
        .type   __unaccounted_init_probe, @function
__unaccounted_init_probe:
        xorl    %eax, %eax
        ret
        .size   __unaccounted_init_probe, .-__unaccounted_init_probe

        .section .init_array,"aw",@init_array
        .p2align 3
        .quad   __unaccounted_init_probe
`;

// A source that legitimately asks for a constructor. Not a negative control in
// the six-way set — it is the boundary case for the initialiser rule, measured
// in both directions so that the rule's reach is a number rather than a claim.
export const CONSTRUCTOR_ATTRIBUTE = {
  name: 'source-declared-constructor',
  file: 'ctl_ctorattr.cc',
  flags: ['-O0'],
  source: `// The source asks for pre-main code itself. The initialiser rule has to tell
// this apart from an .init_array slot nobody asked for.
int sink = 0;

__attribute__((constructor)) static void set_up() { sink = 41; }

int main() { return sink - 41; }
`,
};

// A near-empty translation unit is what the baseline builder compiles. It is
// C++ rather than C on purpose: the C++ startup path is a superset, and a
// baseline taken from C would leave every C++ runtime hook looking introduced.
export const BASELINE_TU = `// Baseline translation unit: as close to empty as a linkable program gets.
int main() { return 0; }
`;

export function writeControls(dir) {
  mkdirSync(dir, { recursive: true });
  const written = [];
  for (const c of [...NEGATIVE_CONTROLS, POSITIVE_CONTROL, CONSTRUCTOR_ATTRIBUTE]) {
    const p = join(dir, c.file);
    writeFileSync(p, c.source, 'utf8');
    written.push(p);
  }
  for (const [name, text] of [['baseline_tu.cc', BASELINE_TU], ['injection.s', INJECTION_ASM]]) {
    const p = join(dir, name);
    writeFileSync(p, text, 'utf8');
    written.push(p);
  }
  return written;
}

if (process.argv[1] && basename(process.argv[1]) === 'controls.mjs') {
  const i = process.argv.indexOf('--write');
  if (i === -1) {
    console.error('usage: node controls.mjs --write <dir>');
    process.exit(2);
  }
  for (const p of writeControls(process.argv[i + 1])) console.log(p);
}
