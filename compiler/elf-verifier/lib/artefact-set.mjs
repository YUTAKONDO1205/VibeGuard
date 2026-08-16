// artefact-set — decides WHICH files a policy run inspects. Never WHETHER one passes.
//
// ── WHY THIS IS A SEPARATE FILE FROM THE VERDICT ────────────────────────────
//
// The verdict for one image belongs to `./artifact-policy.mjs`, reached through
// `../artefact-require.mjs`. Nothing here decides anything about hardening,
// forbidden bytes or exit codes. What was missing was the step BEFORE that one,
// and it had no owner: a build writes a directory, and something has to say
// which of its files are the artefacts the policy is about.
//
// The two mistakes are not symmetric, which is the whole reason this is written
// down rather than inlined as a `.filter()`.
//
//   A wrong VERDICT is loud. It is a finding on a binary somebody looks at, or
//   a missing finding on one somebody later reads with another tool.
//
//   A wrong SELECTION is silent. A file dropped here is a file the policy never
//   sees, and the run still prints `findings=0` and exits 0. That is the shape
//   `compiler/schema/interfaces.md` §7 exists to forbid — "we did not look"
//   reported as "it is clean" — arriving through the one step that has no
//   verdict to be wrong about.
//
// So nothing is dropped anonymously. Every file this module refuses is returned
// with its path and the reason, the runner prints every one of them, and a run
// that selected nothing is not allowed to be exit 0.
//
// ── THE TWO INPUT KINDS DIFFER ON PURPOSE ───────────────────────────────────
//
//   NAMED (`--artifact <p>`)  no magic filter at all. A path a human typed goes
//                             to the consumer whatever it holds, so pointing the
//                             runner at a text file is exit 3 from the consumer
//                             and not a silent skip from here. A named path that
//                             is not on disk is a `problem`, never a skip.
//
//   SCANNED (`--dir <d>`)     filtered on `e_ident` only — the first sixteen
//                             bytes, the same four conditions `./elf.mjs`
//                             readElf checks and with the same wording, so the
//                             two cannot drift into disagreeing about what an
//                             ELF64 LSB image is. A build directory holds `.o`
//                             archives, JSON logs and READMEs; without this the
//                             run would be exit 3 forever and stop being read.
//
// The filter is deliberately shallow: `e_ident` is 16 bytes with no structure to
// get wrong, so "this is not an artefact" is decided on the cheapest possible
// evidence and everything else is left to the reader that actually parses.

import { closeSync, existsSync, openSync, readSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/** e_ident indices and values, from the psABI. Four constants, not a parser. */
const EI_CLASS = 4;
const EI_DATA = 5;
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;

/**
 * Is this file's `e_ident` that of an ELF64 LSB image?
 *
 * Reads sixteen bytes. Returns `{ ok, reason }` and never throws: an unreadable
 * file is a reason, because a directory scan that dies on one permission error
 * has inspected nothing and would report it as nothing found.
 *
 * The four conditions and their wording are `readElf`'s. If that reader ever
 * widens (ELFCLASS32, big-endian), this stays narrower and the consequence is
 * visible: the file is listed as skipped with the byte that decided it, rather
 * than quietly never checked.
 */
export function looksLikeElf64Lsb(path) {
  let fd;
  try {
    fd = openSync(path, 'r');
  } catch (e) {
    return { ok: false, reason: `cannot open: ${e.code ?? e.message}` };
  }
  try {
    const head = Buffer.alloc(16);
    const n = readSync(fd, head, 0, 16, 0);
    // Magic before length, which is the opposite of readElf's order. Both
    // refuse the same files; only the sentence differs, and a build directory
    // is mostly short text files. "shorter than an ELF e_ident (11 bytes)"
    // reads as a truncated binary and sends the reader looking for a broken
    // link; "no ELF magic" says what is actually true of a log file. The
    // length test still runs, for anything too short to have magic at all.
    if (n < 4) return { ok: false, reason: `shorter than an ELF e_ident (${n} bytes)` };
    if (!(head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46)) {
      return { ok: false, reason: 'no ELF magic in e_ident' };
    }
    if (n < 16) return { ok: false, reason: `shorter than an ELF e_ident (${n} bytes)` };
    if (head[EI_CLASS] !== ELFCLASS64) {
      return { ok: false, reason: `e_ident[EI_CLASS]=${head[EI_CLASS]}, only ELFCLASS64 is read` };
    }
    if (head[EI_DATA] !== ELFDATA2LSB) {
      return { ok: false, reason: `e_ident[EI_DATA]=${head[EI_DATA]}, only ELFDATA2LSB is read` };
    }
    return { ok: true, reason: null };
  } catch (e) {
    return { ok: false, reason: `cannot read: ${e.code ?? e.message}` };
  } finally {
    closeSync(fd);
  }
}

/**
 * Build the set of artefacts one policy run will inspect.
 *
 * @param {{dirs?: string[], artifacts?: string[]}} where
 * @returns {{selected: {path: string, source: 'named'|'scanned'}[],
 *            skipped: {path: string, why: string}[],
 *            problems: string[]}}
 *
 * `problems` is the list of things the run was TOLD to do and could not: a
 * named artefact that is not on disk, a `--dir` that is not there, a directory
 * with no regular files in it. They are separated from `skipped` because they
 * mean different things to the exit code — a skip is a file that was looked at
 * and is not an artefact, a problem is an instruction that could not be
 * carried out, and only the second one is `incomplete` on its own.
 *
 * Not recursive. A subdirectory is listed as a skip with that as the reason,
 * so a caller who pointed at a tree rather than a directory of images sees it
 * in the output instead of inferring it from a low count.
 */
export function collectArtefacts({ dirs = [], artifacts = [] } = {}) {
  const selected = [];
  const skipped = [];
  const problems = [];
  const seen = new Set();

  for (const p of artifacts) {
    const abs = resolve(p);
    if (!existsSync(abs)) {
      problems.push(`--artifact ${p}: not present. A named artefact that is not on disk is not a skip — ` +
        'the run was told to check a specific image and could not.');
      continue;
    }
    if (!statSync(abs).isFile()) {
      problems.push(`--artifact ${p}: not a regular file.`);
      continue;
    }
    if (seen.has(abs)) continue;
    seen.add(abs);
    // No e_ident filter here on purpose: see the header.
    selected.push({ path: abs, source: 'named' });
  }

  for (const d of dirs) {
    const abs = resolve(d);
    if (!existsSync(abs)) {
      problems.push(`--dir ${d}: not present. Nothing was scanned there, which is not the same as ` +
        'having scanned it and found nothing.');
      continue;
    }
    if (!statSync(abs).isDirectory()) {
      problems.push(`--dir ${d}: not a directory.`);
      continue;
    }
    let entries;
    try {
      entries = readdirSync(abs).sort();
    } catch (e) {
      problems.push(`--dir ${d}: cannot list: ${e.code ?? e.message}`);
      continue;
    }
    let regularFiles = 0;
    for (const name of entries) {
      const child = join(abs, name);
      let st;
      try {
        st = statSync(child);
      } catch (e) {
        skipped.push({ path: child, why: `cannot stat: ${e.code ?? e.message}` });
        continue;
      }
      if (st.isDirectory()) {
        skipped.push({ path: child, why: 'a directory (this runner does not recurse)' });
        continue;
      }
      if (!st.isFile()) {
        skipped.push({ path: child, why: 'not a regular file' });
        continue;
      }
      regularFiles += 1;
      if (seen.has(child)) continue;
      seen.add(child);
      const m = looksLikeElf64Lsb(child);
      if (m.ok) selected.push({ path: child, source: 'scanned' });
      else skipped.push({ path: child, why: m.reason });
    }
    if (regularFiles === 0) {
      problems.push(`--dir ${d}: holds no regular files. An empty directory is not a clean build.`);
    }
  }

  return { selected, skipped, problems };
}
