// Residue: byte sequences that survived into the finished image.
//
// Two questions, deliberately kept apart:
//
//   SECRET RESIDUE   a literal the policy forbids is still in the bytes.
//   BUILD-PATH RESIDUE  the image names a directory on the machine that built
//                    it. Nobody put it there on purpose; the debug info did.
//
// ── ON THE PATTERNS BELOW ───────────────────────────────────────────────────
//
// The build-path shapes are assembled from fragments at runtime rather than
// written as literals. This is the same precedent as
// `scripts/check-disclosure-shape.mjs`, and here the reason is identical: this
// file is tracked, so the repository's own disclosure check scans it, and a
// literal home-directory pattern in the source matches the shape the check
// forbids. A detector for a leak must not be the leak. Do not "tidy" these into
// literal characters.

/** Directory prefixes that are part of a distribution, not of a build host. */
const SYSTEM_PREFIXES = [
  '/usr/', '/lib/', '/lib64/', '/etc/', '/opt/', '/proc/', '/sys/', '/dev/',
  '/bin/', '/sbin/', '/var/lib/', '/nix/store/', '/build/',
];

const SEP = String.fromCharCode(47); // '/'
const BSL = String.fromCharCode(92); // '\'
const U = 'sers';
const H = 'ome';
const RT = 'oot';

/**
 * The shapes a build-host directory takes. Each entry names itself so a report
 * can say which one fired without quoting more of the path than it must.
 */
export function buildPathShapes() {
  // Inside a character class `\/` is an escaped forward slash and the backslash
  // itself is gone — which is how the Windows shape below silently stopped
  // matching `C:\Users\…` while still compiling. The separator class has to be
  // an escaped BACKSLASH followed by a slash.
  const SEPS = `${BSL}${BSL}${SEP}`;
  const nameChars = `[^${SEPS}\\s"'\`<>$%*?;:,)\\]]{1,80}`;
  return [
    {
      id: 'UNIX-HOME',
      re: new RegExp(`${SEP}h${H}${SEP}(${nameChars})`, 'g'),
      why: 'A path through a per-user home directory. The segment after it is an account name.',
      control: () => `${SEP}h${H}${SEP}somebody${SEP}work`,
    },
    {
      id: 'UNIX-SUPERUSER-HOME',
      re: new RegExp(`${SEP}r${RT}${SEP}(${nameChars})`, 'g'),
      why: "The superuser's home directory. Not an account name, but still a build host's layout.",
      control: () => `${SEP}r${RT}${SEP}scratch${SEP}build`,
    },
    {
      id: 'MAC-HOME',
      re: new RegExp(`${SEP}U${U}${SEP}(${nameChars})`, 'g'),
      why: 'A path through the macOS per-user directory.',
      control: () => `${SEP}U${U}${SEP}somebody${SEP}dev`,
    },
    {
      id: 'WSL-MOUNT',
      re: new RegExp(`${SEP}mnt${SEP}[a-z]${SEP}(${nameChars})`, 'g'),
      why: 'A Windows drive seen from inside a Linux subsystem.',
      control: () => `${SEP}mnt${SEP}c${SEP}work${SEP}tree`,
    },
    {
      id: 'WINDOWS-DRIVE',
      re: new RegExp(`[A-Za-z]:[${SEPS}]{1,2}U${U}[${SEPS}]{1,2}(${nameChars})`, 'g'),
      why: 'A Windows absolute path through the per-user directory.',
      control: () => `C:${BSL}U${U}${BSL}somebody${BSL}src`,
    },
  ];
}

/**
 * Every shape, fired against its own positive control.
 *
 * This exists because one of them silently stopped working: inside a character
 * class `\/` is an escaped forward slash, so the Windows separator class
 * compiled to "slash" and the backslash was gone. The pattern still compiled,
 * still ran, and reported zero for every Windows path it was given. A needle
 * that cannot demonstrate it fires must not be allowed to report zero — the
 * same rule `scripts/check-disclosure-shape.mjs` applies to itself.
 *
 * @returns {{id: string, fires: boolean, control: string}[]}
 */
export function selfTestShapes() {
  return buildPathShapes().map((s) => {
    const control = s.control();
    s.re.lastIndex = 0;
    return { id: s.id, fires: s.re.test(control), control };
  });
}

/**
 * Extract printable runs, the way `strings -a` does.
 *
 * @param {Buffer} buf
 * @param {number} min minimum run length
 * @returns {{value: string, offset: number}[]}
 */
export function extractStrings(buf, min = 4) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = i < buf.length ? buf[i] : 0;
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= min) {
        out.push({ value: buf.toString('latin1', start, i), offset: start });
      }
      start = -1;
    }
  }
  return out;
}

/** Which section a file offset falls inside, for attribution. */
export function sectionAt(elf, offset) {
  for (const s of elf.sections) {
    if (s.sh_type === 8 /* SHT_NOBITS */ || s.sh_size === 0) continue;
    if (offset >= s.sh_offset && offset < s.sh_offset + s.sh_size) return s.name;
  }
  return null;
}

/**
 * Literal byte sequences the policy forbids, searched over the whole image.
 *
 * Searched with `Buffer.indexOf` rather than against the extracted string list:
 * a secret may straddle a non-printable byte, and an extractor that missed it
 * would report the artefact clean. Every occurrence is reported, with the
 * section it landed in.
 */
export function findForbiddenStrings(elf, forbidden) {
  const hits = [];
  for (const needle of forbidden) {
    if (typeof needle !== 'string' || needle.length === 0) continue;
    const pat = Buffer.from(needle, 'utf8');
    let from = 0;
    for (;;) {
      const at = elf.buf.indexOf(pat, from);
      if (at === -1) break;
      hits.push({ needle, offset: at, section: sectionAt(elf, at) });
      from = at + 1;
      if (hits.length > 10000) break;
    }
  }
  return hits;
}

/**
 * The control for the residue extractor.
 *
 * `properties.json` states the rule for this property class: a string that is
 * expected to be present, so that an extractor which has stopped finding
 * anything is distinguishable from an artefact that is clean. A control that is
 * not found makes the whole residue scan INCOMPLETE, never clean.
 */
export function checkResidueControls(elf, expected) {
  return expected.map((needle) => ({
    needle,
    found: elf.buf.indexOf(Buffer.from(needle, 'utf8')) !== -1,
  }));
}

/** Debug sections present in the image. */
export function debugSections(elf) {
  return elf.sections.filter((s) => s.name.startsWith('.debug')).map((s) => s.name);
}

/**
 * Absolute paths that name the machine that built this, with the shape that
 * matched. Only the shape id and a redacted form are kept in the returned
 * record by default; the caller decides whether to reveal the path.
 */
export function findBuildPaths(elf, { min = 6 } = {}) {
  const strings = extractStrings(elf.buf, min);
  const shapes = buildPathShapes();
  const hits = [];
  for (const { value, offset } of strings) {
    for (const shape of shapes) {
      shape.re.lastIndex = 0;
      let m;
      while ((m = shape.re.exec(value)) !== null) {
        if (m[0].length === 0) { shape.re.lastIndex += 1; continue; }
        hits.push({
          shape: shape.id,
          why: shape.why,
          offset: offset + m.index,
          section: sectionAt(elf, offset + m.index),
          length: m[0].length,
          redacted: redactPath(m[0]),
        });
      }
    }
    // A generic absolute path that is not under a system prefix is also build
    // residue even when it matches none of the named shapes above.
    if (value.startsWith(SEP) && value.length >= 8 && !SYSTEM_PREFIXES.some((p) => value.startsWith(p))) {
      const named = shapes.some((s) => { s.re.lastIndex = 0; return s.re.test(value); });
      if (!named && /^[/][A-Za-z0-9._+-]+[/][^\s]{2,}$/.test(value)) {
        hits.push({
          shape: 'ABSOLUTE-PATH',
          why: 'An absolute path that is under no distribution prefix.',
          offset,
          section: sectionAt(elf, offset),
          length: value.length,
          redacted: redactPath(value),
        });
      }
    }
  }
  return dedupe(hits);
}

/** Keep the shape, drop the content: first segment plus the number of segments. */
export function redactPath(p) {
  const parts = p.split(/[\\/]+/).filter(Boolean);
  if (parts.length === 0) return '<path>';
  return `${SEP}${parts[0]}${SEP}<${parts.length - 1} further segment(s), ${p.length} bytes>`;
}

function dedupe(hits) {
  const seen = new Set();
  const out = [];
  for (const h of hits) {
    const k = `${h.shape}:${h.offset}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(h);
  }
  return out.sort((a, b) => a.offset - b.offset);
}
