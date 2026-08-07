// Reading the linker's own list of what it opened: `-Wl,-t`.
//
// WHICH STREAM, AND WHY IT IS WORTH A COMMENT
//
// lld writes this list to STDOUT, not stderr. That is the opposite of where a
// linker's diagnostics go, and a wrapper that captures the pair the usual way
// round — stderr for everything the tool says — records an empty input list and
// then reports a link with no unauthorised inputs in it. Measured: with
// `-Wl,-t`, stdout held eleven lines and stderr held nothing at all.
//
// WHAT IT CONTAINS THAT THE MAP DOES NOT
//
//     /lib/x86_64-linux-gnu/Scrt1.o          crt startup object
//     main.o                                 the user's objects
//     ./libarch.a(arch.o)                    the archive MEMBER that was pulled in
//     /lib/x86_64-linux-gnu/libc.so.6        shared libraries  <- absent from the map
//     /lib64/ld-linux-x86-64.so.2            the dynamic loader <- absent from the map
//
// Shared libraries contribute no input section, so they never appear in a map.
// A link-integrity check built on the map alone therefore cannot see a library
// substitution at all, which is the whole reason both are captured.
//
// Repeats are meaningful and are kept as a count: lld lists a library again
// each time it re-opens it to resolve something, and `libgcc_s.so.1` appeared
// twice in the measured link.

const DIAGNOSTIC = /^(?:clang|clang\+\+|ld|ld\.lld|lld|gcc|g\+\+)[^:]*:\s/i;
const SEVERITY_LINE = /:\s+(?:warning|error|note|fatal error):\s/i;

/** `.so`, `.so.6`, `.so.6.0.1` — a shared object however it is versioned. */
export function looksLikeSharedObject(p) {
  return /\.so(?:\.\d+)*$/.test(p);
}

/**
 * Classify and count the lines of a `-Wl,-t` capture.
 *
 * Nothing is dropped silently: a line that does not look like an input goes to
 * `ignored` with the reason, so a caller can see what the wrapper decided not
 * to treat as an input rather than having to trust that there was nothing.
 *
 * @returns {{entries: Array<{raw: string, kind: 'object'|'archive-member'|'shared-library'|'other', times: number}>,
 *            ignored: Array<{text: string, why: string}>, lines: number}}
 */
export function parseTrace(text) {
  const lines = String(text).split(/\r?\n/);
  const order = [];
  const byRaw = new Map();
  const ignored = [];
  let counted = 0;

  for (const line of lines) {
    if (line.trim() === '') continue;
    counted += 1;
    if (/^\s/.test(line)) {
      ignored.push({ text: line.slice(0, 200), why: 'indented; a continuation of a diagnostic, not a file name' });
      continue;
    }
    if (SEVERITY_LINE.test(line) || DIAGNOSTIC.test(line)) {
      ignored.push({ text: line.slice(0, 200), why: 'a tool diagnostic' });
      continue;
    }
    const raw = line.trimEnd();
    let kind = 'other';
    if (/\([^()]+\)$/.test(raw)) kind = 'archive-member';
    else if (looksLikeSharedObject(raw)) kind = 'shared-library';
    else if (/\.o$/.test(raw) || /\.obj$/.test(raw)) kind = 'object';

    if (kind === 'other') {
      // Not refused — an input can be an object with no extension — but the
      // classification is recorded as unknown rather than guessed at.
      kind = 'other';
    }
    const seen = byRaw.get(raw);
    if (seen) {
      seen.times += 1;
    } else {
      const entry = { raw, kind, times: 1 };
      byRaw.set(raw, entry);
      order.push(entry);
    }
  }

  return { entries: order, ignored, lines: counted };
}
