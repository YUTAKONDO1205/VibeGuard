// Reading the link map that lld writes for `-Wl,-Map=<file>`.
//
// THE FORMAT, AS MEASURED (LLD 18.1.3, x86_64)
//
//     ```
//                  VMA              LMA     Size Align Out     In      Symbol
//                  1650             1650      15e    16 .text
//                  1650             1650       26    16         /lib/x86_64-linux-gnu/Scrt1.o:(.text)
//                  1650             1650       26     1                 _start
//                  1740             1740       56    16         main.o:(.text)
//                  1740             1740       2e     1                 control_fn
//                  2908             2908        8     8         ./libarch.a(arch.o):(.init_array)
//     ```
//
// Four fixed columns — VMA, LMA, Size (all hex, no 0x) and Align (decimal) —
// then ONE space, and then an indentation of 0, 8 or 16 further spaces which is
// the only thing distinguishing an output section from an input section from a
// symbol. The depth is the grammar; there is no other marker, and a parser that
// splits on whitespace loses it. That is why the regex keeps the run of spaces
// as its own capture instead of folding it into `\s+`.
//
// WHAT THE MAP DOES AND DOES NOT CONTAIN
//
// It contains every input that CONTRIBUTED BYTES: objects, archive members, and
// lld's own `<internal>` pseudo-input. It does NOT contain shared libraries —
// a `.so` contributes no input section — and it does not name the linker script.
// Both were checked against a link that used all three. So the map alone cannot
// answer "what went into this link", which is why the wrapper also captures
// `-Wl,-t`, and why the two are cross-checked rather than merged.

const ROW = /^ *([0-9a-fA-F]+) +([0-9a-fA-F]+) +([0-9a-fA-F]+) +(\d+) (\s*)(\S.*)$/;
const HEADER = /^\s*VMA\s+LMA\s+Size\s+Align\s+Out\s+In\s+Symbol\s*$/;

/** True when `text` opens with the header lld writes. Cheap provenance sanity check. */
export function looksLikeLldMap(text) {
  const first = String(text).split(/\r?\n/, 1)[0] ?? '';
  return HEADER.test(first);
}

/** `path:(section)` or `path:(section+0x18)`. Split at the LAST `:(`. */
function splitInField(field) {
  const at = field.lastIndexOf(':(');
  if (at < 0 || !field.endsWith(')')) return null;
  const path = field.slice(0, at);
  const inner = field.slice(at + 2, -1);
  const plus = inner.indexOf('+');
  return {
    path,
    section: plus < 0 ? inner : inner.slice(0, plus),
    offset: plus < 0 ? null : inner.slice(plus + 1),
  };
}

/**
 * Parse a map.
 *
 * Returns the whole thing rather than a summary, because a caller that wants a
 * different question answered should not have to re-parse:
 *
 *   sections   [{name, vma, size, align, contributions: [{path, section, size, symbols: [...]}]}]
 *   inputs     [{path, sections: [name], bytes}]        one entry per distinct input path
 *   symbols    [{name, vma, size, input, section}]      every symbol row, in file order
 *   initArray  {present, contributions: [{path, size, symbols}]}
 *   malformed  [{line, text}]                           rows that did not parse
 *
 * `malformed` is returned rather than thrown on: a map with three unreadable
 * rows out of nine hundred is still worth reading, and a caller that treats any
 * unreadable row as fatal can do so — but it has to decide, not have the
 * decision made for it by a parser that skipped them quietly.
 */
export function parseMap(text) {
  const lines = String(text).split(/\r?\n/);
  const sections = [];
  const symbols = [];
  const malformed = [];
  const inputs = new Map();

  let curSection = null;
  let curContribution = null;
  let sawHeader = false;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '') continue;
    if (HEADER.test(line)) {
      sawHeader = true;
      continue;
    }
    const m = ROW.exec(line);
    if (!m) {
      malformed.push({ line: i + 1, text: line.slice(0, 200) });
      continue;
    }
    const [, vma, , size, align, indent, rest] = m;
    const depth = Math.min(2, Math.floor(indent.length / 8));

    if (depth === 0) {
      curSection = {
        name: rest.trim(),
        vma: parseInt(vma, 16),
        size: parseInt(size, 16),
        align: parseInt(align, 10),
        contributions: [],
      };
      curContribution = null;
      sections.push(curSection);
      continue;
    }

    if (depth === 1) {
      const split = splitInField(rest.trim());
      if (!split) {
        malformed.push({ line: i + 1, text: line.slice(0, 200) });
        curContribution = null;
        continue;
      }
      curContribution = {
        path: split.path,
        section: split.section,
        offset: split.offset,
        vma: parseInt(vma, 16),
        size: parseInt(size, 16),
        symbols: [],
      };
      if (curSection) curSection.contributions.push(curContribution);
      const seen = inputs.get(split.path) ?? { path: split.path, sections: [], bytes: 0 };
      if (!seen.sections.includes(split.section)) seen.sections.push(split.section);
      seen.bytes += curContribution.size;
      inputs.set(split.path, seen);
      continue;
    }

    // depth 2: a symbol. It belongs to the contribution above it; a symbol row
    // with no contribution above it is malformed rather than global.
    if (!curContribution) {
      malformed.push({ line: i + 1, text: line.slice(0, 200) });
      continue;
    }
    const sym = {
      name: rest.trim(),
      vma: parseInt(vma, 16),
      size: parseInt(size, 16),
      input: curContribution.path,
      section: curContribution.section,
    };
    curContribution.symbols.push(sym.name);
    symbols.push(sym);
  }

  const initSection = sections.find((s) => s.name === '.init_array');
  const initArray = {
    present: Boolean(initSection),
    entriesBytes: initSection ? initSection.size : 0,
    contributions: initSection
      ? initSection.contributions.map((c) => ({ path: c.path, size: c.size, symbols: c.symbols.slice() }))
      : [],
  };

  return {
    sawHeader,
    sections,
    inputs: [...inputs.values()],
    symbols,
    initArray,
    malformed,
  };
}

/** The input that defines the symbol sitting exactly at `vma`, or null. */
export function inputDefiningAddress(parsed, vma) {
  if (!Number.isInteger(vma)) return null;
  const hit = parsed.symbols.find((s) => s.vma === vma);
  return hit ? { symbol: hit.name, input: hit.input, section: hit.section } : null;
}
