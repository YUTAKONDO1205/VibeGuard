// What the declared sources actually contain, after preprocessing.
//
// The classifier needs to answer "is this identifier accounted for by the
// source?", and the raw .cc file is the wrong place to ask. `_ZNKSt9type_info
// 4nameEv` is a perfectly ordinary consequence of writing `typeid(*p).name()`,
// but neither `type_info` nor `name` appears in the .cc — they arrive through
// <typeinfo>. Asking the raw file rejects it; asking the preprocessed
// translation unit accepts it, and accepts nothing that the compiler did not
// also see.
//
// The same preprocessing flags are used as the compile, because the flags
// change what the source is: -fsanitize=address defines __SANITIZE_ADDRESS__,
// -DNDEBUG removes bodies, -std= selects different library declarations.

import { execFileSync } from 'node:child_process';
import { basename } from 'node:path';

const IDENT = /[A-Za-z_$][A-Za-z0-9_$]*/g;

// A source may legitimately ask for pre-main code. This matches the *syntax*
// that does it, not the bare word `constructor`, which appears in half of
// libstdc++ as an ordinary identifier.
//
// The tie is at translation-unit granularity: it says "this unit asks for a
// constructor", not "this function is the one it asked for". A unit that
// declares one constructor and ships two initialiser slots therefore passes,
// and that is a stated weakness rather than a hidden one — closing it needs the
// AST, which is a different component's observation point.
const CTOR_ATTRIBUTE = [
  /__attribute__\s*\(\s*\(\s*(?:__)?constructor(?:__)?\b/,
  /\[\[\s*gnu\s*::\s*constructor\b/,
];
const DTOR_ATTRIBUTE = [
  /__attribute__\s*\(\s*\(\s*(?:__)?destructor(?:__)?\b/,
  /\[\[\s*gnu\s*::\s*destructor\b/,
];

export function buildSourceUniverse({ sources, compileFlags = [], cxx = 'clang++-18' }) {
  const identifiers = new Set();
  const sourceBasenames = new Set();
  const failures = [];
  let declaresConstructor = false;
  let declaresDestructor = false;
  for (const src of sources) {
    sourceBasenames.add(basename(src));
    let text;
    try {
      text = execFileSync(cxx, ['-E', '-P', ...compileFlags, src], {
        encoding: 'utf8',
        maxBuffer: 512 * 1024 * 1024,
      });
    } catch (e) {
      failures.push({ source: basename(src), error: String(e.message ?? e).slice(0, 200) });
      continue;
    }
    for (const m of text.matchAll(IDENT)) identifiers.add(m[0]);
    if (CTOR_ATTRIBUTE.some((re) => re.test(text))) declaresConstructor = true;
    if (DTOR_ATTRIBUTE.some((re) => re.test(text))) declaresDestructor = true;
  }
  return {
    available: failures.length === 0 && sources.length > 0,
    identifiers,
    sourceBasenames,
    declaresConstructor,
    declaresDestructor,
    failures,
    sourceCount: sources.length,
    identifierCount: identifiers.size,
  };
}
