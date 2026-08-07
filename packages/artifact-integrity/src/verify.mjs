// The artefact verifier proper: observation -> findings -> exit code.
//
// Namespace VG-ART-0NN, reserved for the artefact verifier in
// `compiler/schema/interfaces.md`. Exit codes are the shared set in
// `compiler/schema/interfaces.md` section 7.
//
// This package deliberately imports NOTHING from `compiler/`. That boundary is
// measured at zero in both directions and this component does not spend it, so
// the exit-code constants and the finding shape are restated here rather than
// imported. `test/boundary.test.mjs` fails if any file in this package ever
// grows such an import.

import {
  readElf, linkForm, isDynamicallyLinked, undefinedSymbols, definedSymbols,
  exportedSymbols, neededLibraries, runPaths, initFunctions, pltCallSites,
  dynstrNames, PT,
} from './elf.mjs';
import { decideAll, STATE, HARDENING_PROPERTIES } from './properties.mjs';
import {
  findForbiddenStrings, checkResidueControls, findBuildPaths, debugSections, extractStrings,
} from './residue.mjs';

export const EXIT_OK = 0;
export const EXIT_TOOL_FAILED = 1;
export const EXIT_FINDINGS = 2;
export const EXIT_INCOMPLETE = 3;
export const EXIT_INTEGRITY = 4;

/**
 * The identifiers this component allocates inside the reserved VG-ART
 * namespace.
 *
 * VG-ART-005 is not a choice: `compiler/schema/policy.schema.json` already
 * pins `artifact.forbidStrings` to it ("a hit is VG-ART-005"), and
 * `compiler/schema/properties.json` repeats the pin. The other three are
 * allocated around that fixed point.
 *
 * VG-ART-001 (artefact digest does not match its pin) is NOT here. It belongs
 * to the component that owns the pin; `compiler/evidence/verify.mjs` already
 * reports a bytes-vs-`artifact.sha256` mismatch as VG-ART-061. This verifier
 * computes and reports the digest and refuses to duplicate the finding.
 */
export const ART = {
  HARDENING_ABSENT: 'VG-ART-003',
  WRITABLE_EXECUTABLE: 'VG-ART-004',
  FORBIDDEN_STRING: 'VG-ART-005',
  BUILD_PATH_RESIDUE: 'VG-ART-006',
  UNAUTHORISED_DEPENDENCY: 'VG-ART-007',
};

export const SEVERITY = {
  'VG-ART-003': 'high',
  'VG-ART-004': 'critical',
  'VG-ART-005': 'critical',
  'VG-ART-006': 'medium',
  'VG-ART-007': 'high',
};

const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

function finding(id, title, detail, where) {
  return {
    id,
    severity: SEVERITY[id],
    title,
    detail,
    where: { kind: 'artifact', path: where.path ?? null, unit: where.unit ?? null, pass: null },
  };
}

/**
 * Everything read out of one image, before any policy is applied.
 * A record, not a verdict: a reader can re-derive every verdict from it.
 */
export function observe(elf) {
  const dynamic = isDynamicallyLinked(elf);
  const imports = undefinedSymbols(elf);
  const props = decideAll(elf);
  return {
    path: elf.path,
    size: elf.size,
    sha256: elf.sha256,
    machine: elf.ehdr.e_machine,
    type: elf.ehdr.e_type,
    linkForm: linkForm(elf),
    dynamicallyLinked: dynamic,
    truncated: elf.truncated,
    sections: elf.sections
      .filter((s) => s.index > 0)
      .map((s) => ({ name: s.name, type: s.sh_type, flags: s.sh_flags, addr: s.sh_addr, size: s.sh_size })),
    executableSections: elf.sections.filter((s) => s.executable).map((s) => s.name),
    writableExecutable: props['no-writable-executable-section'].hits,
    loadSegments: elf.phdrs.filter((p) => p.p_type === PT.LOAD)
      .map((p) => ({ index: p.index, flags: p.p_flags, vaddr: p.p_vaddr, memsz: p.p_memsz })),
    symbolCounts: {
      symtab: elf.symtab.length,
      dynsym: elf.dynsym.length,
      defined: definedSymbols(elf).length,
      undefined: imports.length,
      exported: exportedSymbols(elf).length,
    },
    imports: imports.map((s) => s.name).sort(),
    exports: exportedSymbols(elf).map((s) => s.name).sort(),
    pltCallSites: pltCallSites(elf).map((c) => c.name).sort(),
    dynamicDependencies: neededLibraries(elf),
    runPaths: runPaths(elf),
    notes: elf.notes.map((n) => ({ section: n.section, owner: n.owner, n_type: n.n_type, descsz: n.descsz })),
    buildId: props['build-id'].buildId,
    initFunctions: initFunctions(elf),
    debugSections: debugSections(elf),
    stringCount: extractStrings(elf.buf, 6).length,
    properties: props,
  };
}

/**
 * Apply a policy to one observation.
 *
 * @param {object} elf     result of readElf
 * @param {object} policy  `{ require, forbidStrings, expectStrings, allowedDynamicDependencies }`
 * @returns {{observation: object, findings: object[], incomplete: string[], notObserved: object[]}}
 */
export function verifyArtifact(elf, policy = {}) {
  const require_ = policy.require ?? [];
  const forbidStrings = policy.forbidStrings ?? [];
  const expectStrings = policy.expectStrings ?? [];
  const allowedDeps = policy.allowedDynamicDependencies ?? null;

  const observation = observe(elf);
  const findings = [];
  const incomplete = [];
  const notObserved = [];

  for (const name of require_) {
    if (name === 'no-debug-path') continue; // handled with the residue scan below
    const rec = observation.properties[name];
    if (!rec) {
      incomplete.push(`policy requires an unknown artefact property: ${name}`);
      continue;
    }
    if (rec.state === STATE.PRESENT) continue;
    if (rec.state === STATE.NOT_APPLICABLE) continue;
    if (rec.state === STATE.NOT_OBSERVED) {
      notObserved.push({ property: name, why: rec.note });
      incomplete.push(`${name}: NOT_OBSERVED — ${rec.note ?? 'no reason recorded'}`);
      continue;
    }
    // ABSENT (or LOST) — a required property the artefact does not have.
    if (name === 'no-writable-executable-section') {
      for (const hit of rec.hits) {
        findings.push(finding(ART.WRITABLE_EXECUTABLE,
          'A mapped region is both writable and executable',
          `${hit.kind} ${hit.name} at 0x${hit.addr.toString(16)} (${hit.size} bytes) carries ` +
          (hit.kind === 'section' ? `sh_flags=0x${hit.shFlags.toString(16)} (SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR)` : `p_flags=0x${hit.pFlags.toString(16)} (PF_W|PF_X)`) + '.',
          { path: elf.path, unit: hit.name }));
      }
      continue;
    }
    findings.push(finding(ART.HARDENING_ABSENT,
      `A required hardening property is ${rec.state}: ${name}`,
      describe(rec),
      { path: elf.path, unit: name }));
  }

  // ── residue ───────────────────────────────────────────────────────────────
  const controls = checkResidueControls(elf, expectStrings);
  const brokenControls = controls.filter((c) => !c.found);
  if (brokenControls.length > 0) {
    incomplete.push(
      `the residue extractor did not find ${brokenControls.length} control string(s) that must be present ` +
      `(${brokenControls.map((c) => JSON.stringify(c.needle)).join(', ')}); the scan cannot be reported as clean`);
  }
  observation.residueControls = controls;

  if (forbidStrings.length > 0 && brokenControls.length === 0) {
    const hits = findForbiddenStrings(elf, forbidStrings);
    for (const h of hits) {
      findings.push(finding(ART.FORBIDDEN_STRING,
        'A forbidden byte sequence survived into the artefact',
        `${JSON.stringify(h.needle)} at file offset 0x${h.offset.toString(16)}` +
        (h.section ? ` in ${h.section}` : ' (outside any section)') + '.',
        { path: elf.path, unit: h.section }));
    }
    observation.forbiddenHits = hits.length;
  } else {
    observation.forbiddenHits = forbidStrings.length === 0 ? 0 : null;
  }

  if (require_.includes('no-debug-path')) {
    const paths = findBuildPaths(elf);
    const dbg = observation.debugSections;
    for (const p of paths) {
      findings.push(finding(ART.BUILD_PATH_RESIDUE,
        'The artefact names a directory on the machine that built it',
        `${p.shape} at file offset 0x${p.offset.toString(16)}` +
        (p.section ? ` in ${p.section}` : '') + `: ${p.redacted}. ${p.why}`,
        { path: elf.path, unit: p.section }));
    }
    if (paths.length === 0 && dbg.length > 0) {
      findings.push(finding(ART.BUILD_PATH_RESIDUE,
        'Debug information survived into the artefact',
        `No build-host path matched, but ${dbg.length} debug section(s) are present: ${dbg.join(', ')}. ` +
        'Debug information carries source layout even when no absolute path is spelled out.',
        { path: elf.path, unit: dbg[0] }));
    }
    observation.buildPathHits = paths.length;
  }

  // ── dynamic dependencies ──────────────────────────────────────────────────
  if (allowedDeps !== null) {
    if (!observation.dynamicallyLinked) {
      // Nothing to check; say so rather than passing silently.
      observation.dependencyCheck = 'NOT_APPLICABLE (statically linked)';
    } else {
      const allow = new Set(allowedDeps);
      for (const dep of observation.dynamicDependencies) {
        if (!allow.has(dep)) {
          findings.push(finding(ART.UNAUTHORISED_DEPENDENCY,
            'A dynamic dependency the policy does not authorise',
            `DT_NEEDED ${JSON.stringify(dep)} is not in allowedDynamicDependencies ` +
            `(${allowedDeps.map((d) => JSON.stringify(d)).join(', ') || 'empty'}).`,
            { path: elf.path, unit: dep }));
        }
      }
      for (const rp of observation.runPaths) {
        findings.push(finding(ART.UNAUTHORISED_DEPENDENCY,
          'The artefact carries a library search path',
          `${rp.tag} = ${JSON.stringify(rp.value)}. A search path baked into the image decides at run time ` +
          'which library an authorised DT_NEEDED resolves to, so the allowlist above does not bound it.',
          { path: elf.path, unit: rp.tag }));
      }
      observation.dependencyCheck = 'checked';
    }
  }

  if (elf.truncated.length > 0) {
    incomplete.push(`the image is truncated: could not read ${elf.truncated.slice(0, 5).join(', ')}`);
  }

  return { observation, findings, incomplete, notObserved };
}

function describe(rec) {
  const parts = rec.decidedBy.map((d) => {
    const obs = Array.isArray(d.observed) ? `[${d.observed.join(', ')}]` : String(d.observed);
    return `${d.field}=${obs}`;
  });
  return `${parts.join('; ')}.${rec.note ? ' ' + rec.note : ''}`;
}

/**
 * Exit code for one artefact's result. INCOMPLETE outranks FINDINGS is FALSE:
 * findings outrank incompleteness, because a finding is a thing that was seen
 * and incompleteness is a thing that was not. But 3 is never collapsed into 0.
 */
export function exitCodeFor({ findings, incomplete }, failOn = 'medium') {
  const floor = SEV_RANK[failOn] ?? 1;
  const failing = findings.filter((f) => (SEV_RANK[f.severity] ?? 0) >= floor);
  if (failing.length > 0) return EXIT_FINDINGS;
  if (incomplete.length > 0) return EXIT_INCOMPLETE;
  return EXIT_OK;
}

/** Read a file and verify it. Unreadable-as-ELF is INCOMPLETE, never clean. */
export function verifyPath(path, policy = {}) {
  const elf = readElf(path);
  if (!elf.supported) {
    return {
      observation: { path, supported: false, reason: elf.reason },
      findings: [],
      incomplete: [`${path}: could not be read as ELF64 LSB — ${elf.reason}`],
      notObserved: [],
    };
  }
  return verifyArtifact(elf, policy);
}

export { STATE, HARDENING_PROPERTIES, readElf, dynstrNames };
