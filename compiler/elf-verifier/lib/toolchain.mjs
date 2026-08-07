// The baseline key: (toolchain digest, flag set, link form).
//
// WHY THREE PARTS AND NOT ONE.
//
// The first version of this was "compile an empty translation unit once, keep
// the symbols it produced, subtract them from everything". That is wrong in a
// way that only shows up as false positives later, because what an empty
// translation unit introduces is not a property of the toolchain — it is a
// property of the toolchain *and the flags* *and the link form*:
//
//   -fstack-protector-strong  adds __stack_chk_fail (UND) and __stack_chk_guard
//   -D_FORTIFY_SOURCE=2       adds __memset_chk, __memcpy_chk, __sprintf_chk …
//   -fsanitize=address        adds asan.module_ctor, a .preinit_array slot and
//                             several hundred __asan_* imports
//   -O0 vs -O3                changes which crt helpers survive and adds
//                             .llvm.N / .cold suffixed symbols
//   -static vs dynamic        moves the entire libc surface from UND to defined
//   -shared                   removes _start, Scrt1.o and the PT_INTERP path
//
// Deduct a single-key baseline from any of those and the extra material is
// silently written off as "toolchain", which is exactly the blind spot an
// introduction detector must not have. Key on all three and a mismatch becomes
// a refusal to deduct instead.

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, realpathSync } from 'node:fs';
import { basename } from 'node:path';
import { sha256Hex, sha256OfJson } from './canonical.mjs';
import { ET, PT, DT, DF_1, dynTag } from './elf.mjs';

/**
 * Files whose bytes decide what an empty translation unit turns into. The C
 * runtime startup objects are in here for the same reason the driver is: a
 * distribution upgrade that leaves `clang++ --version` unchanged can still ship
 * a different crtbeginS.o, and the baseline taken before it no longer describes
 * the builds taken after it.
 */
const DIGESTED_ROLES = [
  { role: 'cxx-driver', kind: 'prog', query: null },
  { role: 'linker', kind: 'prog', query: 'ld' },
  { role: 'Scrt1.o', kind: 'file', query: 'Scrt1.o' },
  { role: 'crt1.o', kind: 'file', query: 'crt1.o' },
  { role: 'crti.o', kind: 'file', query: 'crti.o' },
  { role: 'crtn.o', kind: 'file', query: 'crtn.o' },
  { role: 'crtbeginS.o', kind: 'file', query: 'crtbeginS.o' },
  { role: 'crtendS.o', kind: 'file', query: 'crtendS.o' },
  { role: 'libstdc++.so', kind: 'file', query: 'libstdc++.so' },
];

function digestFile(p) {
  try {
    return sha256Hex(readFileSync(p));
  } catch {
    return null;
  }
}

/**
 * `-print-file-name` / `-print-prog-name` return one absolute path on stdout and
 * nothing else. That is a machine-readable answer to a machine-readable
 * question, not a rendering of a structure, which is the distinction the "do not
 * read human-readable output" rule is actually about — there is no formatting
 * here for a toolchain upgrade to change.
 */
export function toolchainIdentity(cxx = 'clang++-18') {
  const entries = [];
  const notes = [];
  let driverPath = null;
  try {
    driverPath = realpathSync(execFileSync('which', [cxx], { encoding: 'utf8' }).trim());
  } catch {
    driverPath = null;
  }
  for (const spec of DIGESTED_ROLES) {
    let p = null;
    if (spec.query === null) {
      p = driverPath;
    } else if (driverPath) {
      try {
        const flag = spec.kind === 'prog' ? '-print-prog-name=' : '-print-file-name=';
        const got = execFileSync(cxx, [`${flag}${spec.query}`], { encoding: 'utf8' }).trim();
        // The driver echoes the query back unchanged when it cannot find the
        // file. Treat that as absent rather than digesting a relative name.
        p = got && got !== spec.query && existsSync(got) ? realpathSync(got) : null;
      } catch {
        p = null;
      }
    }
    if (!p) {
      notes.push(`${spec.role}: not resolved`);
      continue;
    }
    const d = digestFile(p);
    if (!d) {
      notes.push(`${spec.role}: unreadable at resolve time`);
      continue;
    }
    // Basename only. Absolute paths must not appear in a record.
    entries.push({ role: spec.role, file: basename(p), sha256: d });
  }
  entries.sort((a, b) => (a.role < b.role ? -1 : a.role > b.role ? 1 : 0));
  const digest = sha256OfJson(entries);
  return { digest, entries, unresolved: notes, driver: cxx };
}

/**
 * Normalise a compile/link command line down to the part that decides what gets
 * introduced.
 *
 * Order is preserved rather than sorted, because `-O0 -O3` and `-O3 -O0` are
 * different compilations and a sorted key would call them the same. The cost is
 * that a semantically identical reordering produces a different key and so a
 * refusal to deduct — which is the safe direction to be wrong in, and is
 * reported as a mismatch rather than absorbed.
 */
export function normaliseFlags(argv) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-o' || a === '-MF' || a === '-MT' || a === '-MQ' || a === '-isysroot') {
      i++;
      continue;
    }
    if (a === '-c' || a === '-S' || a === '-E') continue;
    if (a.startsWith('-')) {
      // `-fpass-plugin=/home/…/libMarkerPass.so` carries an absolute path, and
      // an absolute path must not reach a record. Replacing it with the
      // basename *and the digest of the file* removes the path and makes the
      // key stronger at the same time: two plugins with the same file name and
      // different bytes are two different configurations, and a baseline taken
      // under one of them must not be deducted from a build under the other.
      const eq = a.indexOf('=');
      if (eq !== -1) {
        const value = a.slice(eq + 1);
        if (value.startsWith('/') && existsSync(value)) {
          const d = sha256Hex(readFileSync(value));
          out.push(`${a.slice(0, eq)}=${basename(value)}@sha256:${d}`);
          continue;
        }
      }
      out.push(a);
      continue;
    }
    // A bare word is an input path. Paths are per-machine and per-fixture, so
    // they are not part of the key.
  }
  return out;
}

export function flagsDigest(flags) {
  return sha256OfJson(flags);
}

/**
 * Link form, decided from the artefact's own header rather than from the
 * command line, so that a build whose flags say one thing and whose output says
 * another is caught instead of trusted.
 */
export function linkForm(elf) {
  const t = elf.ehdr.e_type;
  if (t === ET.REL) return { form: 'object', decidedBy: [{ field: 'Elf64_Ehdr.e_type', observed: t, note: 'ET_REL=1' }] };
  const f1 = dynTag(elf, DT.FLAGS_1);
  const pie = f1 !== null && (Number(f1.value & 0xffffffffn) & DF_1.PIE) !== 0;
  const interp = elf.phdrs.some((p) => p.p_type === PT.INTERP);
  const decidedBy = [
    { field: 'Elf64_Ehdr.e_type', observed: t },
    { field: 'DT_FLAGS_1 & DF_1_PIE', observed: pie ? 1 : 0 },
    { field: 'PT_INTERP present', observed: interp ? 1 : 0 },
  ];
  if (t === ET.DYN) return { form: pie ? 'exec-pie' : 'shared', decidedBy };
  if (t === ET.EXEC) return { form: interp ? 'exec-nopie-dynamic' : 'exec-static', decidedBy };
  return { form: `elf-type-${t}`, decidedBy };
}

export function baselineKey({ toolchainDigest, flags, form }) {
  const fd = flagsDigest(flags);
  return {
    toolchainDigest,
    flagsDigest: fd,
    flags,
    form,
    id: sha256OfJson({ toolchainDigest, flagsDigest: fd, form }),
  };
}

/** Human-facing, short, and unambiguous enough to name a directory with. */
export function keyPathParts(key) {
  return [key.toolchainDigest.slice(0, 16), key.form, key.flagsDigest.slice(0, 16)];
}
