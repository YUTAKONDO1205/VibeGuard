// Assembling one link's observation from the three things the wrapper captured:
// the map it made the linker write, the input trace the linker printed, and the
// bytes of the artefact.
//
// PROVENANCE IS PART OF THE OBSERVATION, NOT METADATA ABOUT IT
//
// `mapProvenance.producedBy` travels with the parsed map all the way to the
// verdict, and the verdict refuses to run unless it says `wrapper`. That is
// deliberately awkward: it would be easier to check the provenance once at the
// CLI and then pass a plain parsed map around. But then every other caller of
// the verdict — a future batch mode, a test helper, a fixer — would have a way
// to get a verdict out of a map of unknown origin, and one of them eventually
// would. The awkwardness is the point.
//
// TWO OBSERVATIONS, KEPT SEPARATE
//
// The map and the trace see different things (see map-parse.mjs and
// trace-parse.mjs). They are recorded as two sources and merged only into a
// `sources` list per input, never into a single list with the provenance
// dropped, so that an input which appears in one and not the other is visible
// rather than smoothed over. That disagreement is VG-LINK-008.

import { basename } from 'node:path';

import { parseMap, inputDefiningAddress } from './map-parse.mjs';
import { parseTrace, looksLikeSharedObject } from './trace-parse.mjs';
import { parseLinkCommand, screenLinkCommand } from './cmdline.mjs';
import { makeRef, normalisePath } from './refs.mjs';
import { readElfHeader } from './elf.mjs';
import { sha256Hex } from './canonical.mjs';

/** The only provenance a verdict will accept. Constructed by the runner, nowhere else. */
export const PRODUCED_BY_WRAPPER = 'wrapper';

/**
 * @param {object} a
 * @param {string} a.linkRoot        absolute directory the link ran in
 * @param {string[]} a.argv          the link command, program first
 * @param {string} a.mapText
 * @param {object} a.mapProvenance   {producedBy, mapPath, existedBefore, writtenByThisRun}
 * @param {string} a.traceText
 * @param {string|null} a.artifactPath
 * @param {Buffer|null} a.artifactBytes
 */
export function buildObservation({
  linkRoot,
  argv,
  mapText,
  mapProvenance,
  traceText,
  artifactPath = null,
  artifactBytes = null,
}) {
  const root = normalisePath(linkRoot);
  const problems = [];

  const command = parseLinkCommand(argv);
  const screen = screenLinkCommand(command);

  const map = parseMap(mapText ?? '');
  const trace = parseTrace(traceText ?? '');

  if (!map.sawHeader) {
    problems.push({ what: 'map', why: 'the map does not open with the column header lld writes; it may not be a link map at all' });
  }
  for (const m of map.malformed) {
    problems.push({ what: 'map-row', why: `line ${m.line} did not parse`, text: m.text });
  }
  for (const ig of trace.ignored) {
    problems.push({ what: 'trace-line', why: ig.why, text: ig.text });
  }

  /** ref -> input entry */
  const byRef = new Map();
  const touch = (raw, source) => {
    const r = makeRef(raw, root);
    let e = byRef.get(r.ref);
    if (!e) {
      e = {
        ref: r.ref,
        base: r.base,
        kind: r.member ? 'archive-member' : looksLikeSharedObject(r.base) ? 'shared-library' : 'object',
        archive: r.archive,
        member: r.member,
        pathWithheld: r.pathWithheld,
        sources: [],
        sections: [],
        bytes: 0,
        times: 0,
      };
      if (r.ref.startsWith('internal:')) e.kind = 'linker-generated';
      byRef.set(r.ref, e);
      if (r.pathWithheld) {
        problems.push({ what: 'input-path-withheld', why: r.withheldReason, text: r.ref });
      }
    }
    if (!e.sources.includes(source)) e.sources.push(source);
    return e;
  };

  for (const mi of map.inputs) {
    const e = touch(mi.path, 'map');
    for (const s of mi.sections) if (!e.sections.includes(s)) e.sections.push(s);
    e.bytes += mi.bytes;
  }
  for (const te of trace.entries) {
    const e = touch(te.raw, 'trace');
    e.times += te.times;
    if (te.kind === 'shared-library') e.kind = 'shared-library';
  }

  const inputs = [...byRef.values()].sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));

  const refOf = (rawPath) => makeRef(rawPath, root).ref;

  const symbols = map.symbols.map((s) => ({
    name: s.name,
    section: s.section,
    vma: s.vma,
    size: s.size,
    input: refOf(s.input),
  }));

  const initArray = {
    present: map.initArray.present,
    entriesBytes: map.initArray.entriesBytes,
    contributions: map.initArray.contributions.map((c) => ({
      input: refOf(c.path),
      size: c.size,
      symbols: c.symbols.slice(),
    })),
  };

  // ---- artefact -------------------------------------------------------------
  let artifact = null;
  if (artifactBytes) {
    const header = readElfHeader(artifactBytes);
    const rel = artifactPath ? makeRef(artifactPath, root) : null;
    artifact = {
      path: rel ? rel.ref : null,
      pathWithheld: rel ? rel.pathWithheld : false,
      size: artifactBytes.length,
      sha256: sha256Hex(artifactBytes),
      elf: header.ok
        ? { class: header.class, endian: header.endian, type: header.type, entry: header.entry, machine: header.machine }
        : null,
    };
    if (!header.ok) problems.push({ what: 'artifact', why: `ELF header not readable: ${header.why}` });
  } else {
    problems.push({ what: 'artifact', why: 'the artefact was not read, so nothing about it was observed' });
  }

  // ---- entry point ----------------------------------------------------------
  let entry = { address: null, symbol: null, input: null, resolved: 'NOT_OBSERVED' };
  if (artifact?.elf) {
    const at = inputDefiningAddress(map, artifact.elf.entry);
    entry = at
      ? { address: artifact.elf.entry, symbol: at.symbol, input: refOf(at.input), resolved: 'PRESENT' }
      : { address: artifact.elf.entry, symbol: null, input: null, resolved: 'ABSENT' };
    if (!at) {
      problems.push({ what: 'entry-point', why: `no symbol in the map sits at the entry address 0x${artifact.elf.entry.toString(16)}` });
    }
  }

  const scripts = command.linkerScripts.map((s) => ({ ref: makeRef(s, root).ref, base: basename(s) }));

  return {
    provenance: {
      map: {
        producedBy: mapProvenance?.producedBy ?? 'unknown',
        existedBefore: mapProvenance?.existedBefore ?? null,
        writtenByThisRun: mapProvenance?.writtenByThisRun ?? null,
        nonce: mapProvenance?.nonce ?? null,
      },
      trace: { stream: 'stdout' },
    },
    command: {
      program: basename(command.program),
      linker: command.linker,
      output: command.output ? makeRef(command.output, root).ref : null,
      options: command.linkerOptions,
      scripts,
      positionalInputs: command.positionalInputs.map((p) => makeRef(p, root).ref),
      refusals: screen.refusals,
      opaque: screen.opaque,
    },
    inputs,
    symbols,
    initArray,
    entry,
    sections: map.sections.map((s) => ({ name: s.name, vma: s.vma, size: s.size, align: s.align })),
    artifact,
    problems,
    counts: {
      mapInputs: map.inputs.length,
      traceEntries: trace.entries.length,
      symbols: symbols.length,
      sections: map.sections.length,
    },
  };
}
