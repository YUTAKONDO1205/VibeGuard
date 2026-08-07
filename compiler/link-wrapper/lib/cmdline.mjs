// Reading the link command line, and refusing the ones that would let the
// caller choose what the wrapper gets to see.
//
// THE ONE RULE THAT MATTERS HERE
//
// The map must be produced BY the wrapper. If the caller may name it, the
// caller supplies it, and then the verdict is computed from the attacker's
// account of the link rather than from the link. So every flag that would let
// the caller redirect, suppress or pre-empt the map is refused BEFORE the
// linker is invoked — not filtered out, refused, because a wrapper that
// silently drops a flag has changed the build it claims to be observing.
//
// The refused set is written out in full rather than matched by prefix. `-M`
// and `-Map` differ by two characters and do completely different things; a
// prefix test that catches both also catches `-Machine` if a linker ever grows
// one, and a prefix test narrow enough to avoid that misses `--print-map`.

/** Linker options that write, redirect or suppress the map. */
export const MAP_OPTIONS = Object.freeze([
  '-Map', '--Map', '-M', '--print-map', '--map', '--Map-file', '--map-file',
]);

function optionName(tok) {
  const eq = tok.indexOf('=');
  return eq < 0 ? tok : tok.slice(0, eq);
}

/** Everything after `-Wl,` split on commas, which is how the driver passes it on. */
function wlParts(tok) {
  return tok.slice(4).split(',');
}

const SCRIPT_OPTIONS = new Set(['-T', '--script', '--default-script', '-dT']);
const SCRIPT_SUFFIX = /\.(?:ld|lds|x|ldscript)$/i;

// `-T` takes its argument glued (`-Textra.ld`), separated (`-T extra.ld`) or
// with an equals sign. GNU ld also spells four SECTION-ADDRESS options the same
// way — `-Ttext=0x1000`, `-Tdata`, `-Tbss`, `-Trodata` — and those are not
// scripts. Treating them as scripts would report a linker script on a build
// that merely placed a section, which is a false positive at `high`.
const SECTION_ADDRESS = /^-T(?:text-segment|text|data|bss|rodata|ldata)(?:$|=)/;

/**
 * The script a token names.
 *   null  the token is not a script option
 *   ''    it is, and the filename is the NEXT token
 *   other it is, and this is the filename
 */
function scriptArgument(tok) {
  const eq = tok.indexOf('=');
  const name = eq < 0 ? tok : tok.slice(0, eq);
  if (SCRIPT_OPTIONS.has(name)) return eq < 0 ? tok.slice(name.length) : tok.slice(eq + 1);
  if (SECTION_ADDRESS.test(tok)) return null;
  if (/^-T./.test(tok)) return tok.slice(2);
  return null;
}

/**
 * @param {string[]} argv  the full link command, program first
 * @param {{scriptSuffixes?: RegExp}} [opts]
 * @returns {{
 *   program: string,
 *   linker: string|null,
 *   output: string|null,
 *   linkerOptions: string[],
 *   linkerScripts: string[],
 *   positionalInputs: string[],
 *   mapOptions: string[],
 *   responseFiles: string[],
 *   traceAlreadyRequested: boolean
 * }}
 */
export function parseLinkCommand(argv, opts = {}) {
  const suffix = opts.scriptSuffixes ?? SCRIPT_SUFFIX;
  const args = Array.isArray(argv) ? argv.map(String) : [];
  const program = args[0] ?? '';
  const rest = args.slice(1);

  const out = {
    program,
    direct: false,
    linker: null,
    output: null,
    linkerOptions: [],
    linkerScripts: [],
    positionalInputs: [],
    mapOptions: [],
    responseFiles: [],
    traceAlreadyRequested: false,
  };

  // When the program IS a linker, its own options are not behind `-Wl,`.
  const directLinker = /(?:^|[\/\\])(?:ld|ld\.lld|ld\.gold|ld\.bfd|lld|lld-link|ld64\.lld)(?:-\d+)?$/.test(program);
  out.direct = directLinker;
  if (directLinker) out.linker = program.replace(/^.*[\\/]/, '');

  const noteLinkerOption = (name, full) => {
    out.linkerOptions.push(full);
    if (MAP_OPTIONS.includes(name)) out.mapOptions.push(full);
    if (name === '-t' || name === '--trace') out.traceAlreadyRequested = true;
  };

  for (let i = 0; i < rest.length; i += 1) {
    const tok = rest[i];

    if (tok.startsWith('@')) {
      out.responseFiles.push(tok);
      continue;
    }

    if (tok === '-o') {
      out.output = rest[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (tok.startsWith('-o') && tok.length > 2 && !tok.startsWith('-obj')) {
      out.output = tok.slice(2);
      continue;
    }

    if (tok.startsWith('-fuse-ld=')) {
      out.linker = tok.slice('-fuse-ld='.length);
      continue;
    }

    if (tok.startsWith('-Wl,')) {
      const parts = wlParts(tok);
      for (let j = 0; j < parts.length; j += 1) {
        const p = parts[j];
        const name = optionName(p);
        noteLinkerOption(name, p);
        // `-Wl,-T,file`, `-Wl,-T=file` and `-Wl,-Tfile` all reach the linker the same way.
        const arg = scriptArgument(p);
        if (arg !== null) {
          if (arg !== '') out.linkerScripts.push(arg);
          else if (j + 1 < parts.length) {
            out.linkerScripts.push(parts[j + 1]);
            j += 1;
          }
        }
      }
      continue;
    }

    if (directLinker) {
      const name = optionName(tok);
      if (tok.startsWith('-')) {
        noteLinkerOption(name, tok);
        const arg = scriptArgument(tok);
        if (arg !== null) {
          if (arg !== '') out.linkerScripts.push(arg);
          else if (rest[i + 1] !== undefined) {
            out.linkerScripts.push(rest[i + 1]);
            i += 1;
          }
        }
        continue;
      }
    }

    if (tok.startsWith('-')) continue; // a compiler option; not ours to interpret
    out.positionalInputs.push(tok);
    if (suffix.test(tok)) out.linkerScripts.push(tok);
  }

  return out;
}

/**
 * Whether this command line may be run under the wrapper at all.
 *
 * Two separate answers, because they have different exit codes:
 *   `refusals`  the caller tried to control the observation -> integrity, exit 4
 *   `opaque`    the command line could not be fully read   -> incomplete, exit 3
 */
export function screenLinkCommand(parsed) {
  const refusals = [];
  const opaque = [];
  for (const m of parsed.mapOptions) {
    refusals.push({
      what: m,
      why: 'the map is produced by the wrapper; a caller that names it supplies it, and a verdict computed from a supplied map is an attacker-chosen account of the link',
    });
  }
  for (const r of parsed.responseFiles) {
    opaque.push({
      what: r,
      why: 'a response file can carry any linker option, including one that redirects the map; the command line is therefore not fully observed',
    });
  }
  return { refusals, opaque };
}
