/**
 * The compile-link-read plumbing of the which-wipe reading, in one place.
 *
 * This is the code that turns three source texts into three integers: four
 * compiles, one full-LTO link and one objdump read per variant. It used to live
 * inside tools/which-wipe-survived.mjs, where no test could reach it. It is here
 * so that the integration check (tools/check-which-wipe-plumbing.mjs) exercises
 * THE SAME code the tool runs, rather than a second copy that can agree with the
 * tool while both are wrong.
 *
 * What it adds over the version it replaces: the sha256 of the source that was
 * on disk when the compiler read it, and the sha256 of the object that came out.
 * A variant is a claim that the compiler saw a different source; those two
 * digests are the evidence for the claim, and they are the one thing that
 * separates "three builds" from "one build read three times" -- a stale work
 * directory, a write that did not land, a cut that deleted nothing. All three of
 * those read out as "deleting it changed nothing", which is this tool's headline
 * answer.
 *
 * THE EDITED UNIT IS COMPILED FROM ONE PATH, AND THE PATH CARRIES NO TAG.
 * This is the whole reason the object digest is worth taking, and it was wrong
 * until 2026-09-14. The three variants used to be written to `<tag>_use.c` and
 * compiled to `<tag>_use.o`, and clang puts the source path into what it emits:
 * measured in WSL Ubuntu-24.04, two BYTE-IDENTICAL .c files under different
 * filenames, at `clang-18 -O2 -flto -c`, produce objects whose sha256 DIFFER --
 * and so they do without `-flto` too. Three distinct digests were therefore
 * guaranteed by the three filenames, whatever the sources said, so the gate that
 * compared them could not fail. It would have passed a cut that deleted nothing,
 * which is precisely the failure it exists to detect.
 *
 * So `editedPaths()` below takes no tag: every variant is written to the same
 * `use.c` and compiled to the same `use.o`, in build order, each one linked and
 * read before the next is written. A path difference cannot contribute to a
 * digest difference any more, and what is left to differ is the source text --
 * which is the thing the gate claims to be testing. Two variants built from the
 * same bytes now collide, loudly, at lib/plumbing-gates.mjs.
 *
 * The same fixed path is what makes a write that did not land visible: the file
 * is read back after it is written and before it is compiled, and a mismatch is
 * a BuildFailure rather than a build of whatever was there before.
 *
 * Object digests are taken on the PRE-LINK object of the edited unit, not on the
 * linked executable, and the distinction matters: the whole finding is that the
 * linked program is unchanged when the subject's wipe is deleted, so two of the
 * three executables are EXPECTED to be byte-identical. The bitcode still carries
 * the call the source asked for, so the three objects are not.
 *
 * Nothing here decides anything. Grading is lib/record.mjs's whichWipeSurvived()
 * and ordering is lib/plumbing-gates.mjs; this file runs processes and reports
 * what they did, including their failures, as data.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The disassembly reader, which is shared with gcc-repair's objdump oracle. */
export const READ_WIPE = join(HERE, '..', 'tools', 'read-wipe.py');

export class BuildFailure extends Error {
  constructor(step, message, detail = {}) {
    super(message);
    this.name = 'BuildFailure';
    this.step = step;
    this.detail = detail;
  }
}

const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

/** The sha256 of a string, for comparing a source TEXT with what landed on disk. */
export const digestOfText = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

/**
 * Where the edited unit is written and where it is compiled to.
 *
 * THERE IS NO TAG IN EITHER NAME, ON PURPOSE. See the header: the compiler puts
 * the source path into the object, so per-variant filenames made three distinct
 * object digests unconditionally and the gate that compares them could not fail.
 * One path for all three variants means that a digest which differs differs
 * because the SOURCE TEXT differed.
 *
 * The cost of the shared path is that the variants must be built one at a time,
 * each linked and read before the next is written. runFamily() does exactly
 * that, in the order VARIANTS names.
 */
export function editedPaths(work, edited = 'use') {
  return { source: join(work, `${edited}.c`), object: join(work, `${edited}.o`) };
}

/**
 * Write one variant's source and prove it is what the compiler will read.
 *
 * Returns the digest of the bytes that came BACK off disk, not of the string
 * that went in. The distinction is the point: every variant is written to the
 * same path (see editedPaths()), so a write that did not land leaves the
 * PREVIOUS variant there, it compiles, it links, it reads -- and the reading
 * is `deleting it changed nothing`, which is this lane's headline answer.
 *
 * `write` and `read` are injectable for one reason: a short write cannot be
 * arranged on a real filesystem from a test, and a guard whose failure branch
 * has never been executed is a guard nobody has checked.
 */
export function writeAndVerify({ path, text, tag, edited, write = writeFileSync, read = readFileSync }) {
  write(path, text, 'utf8');
  const landed = read(path, 'utf8');
  if (landed !== text) {
    throw new BuildFailure('write', `${tag}/${edited}.c is not on disk as it was written (${landed.length} chars read back for ${text.length} written): the compiler would have read the previous variant`, { tag, edited });
  }
  return digestOfText(landed);
}

/** Run a command. rc is data here; the caller decides what a non-zero means. */
export function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  return {
    cmd, args,
    rc: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    spawnError: r.error ? `${r.error.code ?? r.error.name}` : null,
  };
}

/**
 * Is the toolchain this measurement needs actually here?
 *
 * Returns the list of MISSING tools, each with the probe that failed, rather
 * than a boolean: a caller that refuses has to be able to name what it is
 * missing, and "no compiler on this machine" and "the measurement disagreed"
 * are different answers that must not share an exit code.
 */
export function missingTools({ cc = 'clang-18', ld = 'lld-18', objdump = process.env.LTOW_OBJDUMP || 'objdump', python = 'python3' } = {}) {
  const probes = [
    { tool: cc, argv: [cc, ['--version']] },
    // `-fuse-ld=lld-18` makes the driver look for `ld.lld-18`; probe the binary
    // the link will actually need, not the spelling the flag uses.
    { tool: `ld.${ld}`, argv: [`ld.${ld}`, ['--version']] },
    { tool: objdump, argv: [objdump, ['--version']] },
    { tool: python, argv: [python, ['--version']] },
  ];
  const missing = [];
  for (const p of probes) {
    const r = run(p.argv[0], p.argv[1]);
    if (r.spawnError || r.rc !== 0) missing.push({ tool: p.tool, why: r.spawnError ? `cannot be spawned (${r.spawnError})` : `--version exited ${r.rc}` });
  }
  return missing;
}

/**
 * Build one variant of a family and read the fill in its absorbed body.
 *
 * @param spec.units      the units compiled beside the edited one, in build order.
 * @param spec.opaque     which of those are compiled WITHOUT -flto. This is the
 *                        opacity the control depends on: with the consumer
 *                        visible to the link, the buffer is promoted out of
 *                        memory and the control stops being a control.
 * @param spec.edited     the unit the cut rewrites (its text is `useSource`).
 * @param spec.exec       injected process runner; defaults to run(). It is here
 *                        so that test/build-variants.test.mjs can drive this
 *                        function's PATH DISCIPLINE with a compiler whose output
 *                        depends on the source path -- which is what the real
 *                        one was measured to do.
 * @returns {{objects, sourceDigest, useDigest, exe, subject, control, objdump}}
 * @throws  {BuildFailure} naming the step that failed and its stderr.
 */
export function buildAndRead(spec) {
  const {
    cc = 'clang-18', ld = 'lld-18', opt = '-O2',
    fixtures, work, tag, useSource,
    units = ['io', 'main', 'wipe'], opaque = ['io'], edited = 'use',
    caller = 'main', helper = 'secure_wipe', bufferBytes = 32,
    controlCaller = null, controlBytes = null,
    python = 'python3', exec = run, write = writeFileSync, read = readFileSync,
  } = spec;

  const objects = {};
  const objs = [];
  for (const unit of units) {
    const src = join(fixtures, `${unit}.c`);
    const obj = join(work, `${tag}_${unit}.o`);
    const flto = opaque.includes(unit) ? [] : ['-flto'];
    const r = exec(cc, [opt, ...flto, '-c', src, '-o', obj]);
    if (r.spawnError || r.rc !== 0) throw new BuildFailure('compile', `${tag}/${unit}.c did not compile: ${(r.stderr || r.spawnError || '').slice(0, 400)}`);
    objects[unit] = sha256(obj);
    objs.push(obj);
  }

  // One path, no tag: see editedPaths(). The read-back is the other half of the
  // same guarantee -- a write that silently did not land would otherwise be
  // compiled as the previous variant and read as "deleting it changed nothing".
  const { source: usePath, object: useObj } = editedPaths(work, edited);
  const sourceDigest = writeAndVerify({ path: usePath, text: useSource, tag, edited, write, read });

  // Remove the previous variant's object FIRST. Sharing one path is what stops a
  // filename from contributing to a digest, but it also left the existsSync guard
  // below dead from the second variant on: a compiler that exited 0 and wrote
  // nothing would have had last variant's object digested in its place. That does
  // not escape the run -- two variants carrying one digest collide at
  // lib/plumbing-gates.mjs -- but it arrives as "two variants are identical",
  // which is a true sentence about the wrong thing. Deleting first makes the
  // guard that names the real cause reachable for every variant.
  rmSync(useObj, { force: true });
  const rc = exec(cc, [opt, '-flto', '-c', usePath, '-o', useObj]);
  if (rc.spawnError || rc.rc !== 0) throw new BuildFailure('compile', `${tag}/${edited}.c did not compile: ${(rc.stderr || rc.spawnError || '').slice(0, 400)}`);
  if (!existsSync(useObj)) throw new BuildFailure('compile', `${tag}/${edited}.c: the compiler exited 0 and wrote no object`);
  objects[edited] = sha256(useObj);
  objs.push(useObj);

  const exe = join(work, `app_${tag}`);
  const rl = exec(cc, [opt, '-flto', `-fuse-ld=${ld}`, ...objs, '-o', exe]);
  if (rl.spawnError || rl.rc !== 0) throw new BuildFailure('link', `${tag} did not link: ${(rl.stderr || rl.spawnError || '').slice(0, 400)}`);

  const rr = exec(python, [
    READ_WIPE, exe, caller, helper ?? '-', String(bufferBytes),
    controlCaller ?? caller, String(controlBytes ?? bufferBytes),
  ]);
  if (rr.spawnError || rr.rc !== 0) throw new BuildFailure('read', `${tag} could not be disassembled: rc=${rr.rc} ${(rr.stderr || rr.spawnError || '').slice(0, 300)}`);
  let j;
  try { j = JSON.parse(rr.stdout); } catch { throw new BuildFailure('read', `${tag}: the reader did not print JSON`); }

  return {
    tag,
    objects,
    sourceDigest,
    useDigest: objects[edited],
    exeDigest: sha256(exe),
    exe,
    subject: j.subject,
    control: j.control,
    objdump: j.objdump,
  };
}

/**
 * Read one already-linked executable again, for a different function. Used for
 * diagnosis when a gate fails: what a failed reading was looking at is part of
 * the failure, not a separate investigation.
 *
 * IT DOES NOT SWALLOW ITS FAILURES. It used to return null for all of them --
 * reader missing, executable gone, output unparseable -- and a diagnosis that
 * prints `null` beside a function name says "this function is not in the
 * binary", which is a reading, when what happened may have been that no read was
 * taken at all. The two are kept apart: `ok: true` with a reading (including
 * objdump_fill's own NOT_OBSERVED, which IS a reading), or `ok: false` with the
 * reason the read could not be taken.
 */
export function readAgain({ exe, caller, helper = null, bufferBytes = 32, python = 'python3', exec = run }) {
  const r = exec(python, [READ_WIPE, exe, caller, helper ?? '-', String(bufferBytes), caller, String(bufferBytes)]);
  if (r.spawnError) return { ok: false, reading: null, why: `the reader could not be spawned (${r.spawnError})` };
  if (r.rc !== 0) return { ok: false, reading: null, why: `the reader exited ${r.rc}: ${(r.stderr || '').trim().slice(0, 200) || 'no stderr'}` };
  let parsed;
  try { parsed = JSON.parse(r.stdout); } catch { return { ok: false, reading: null, why: 'the reader did not print JSON' }; }
  if (!parsed || typeof parsed.subject !== 'object' || parsed.subject === null) {
    return { ok: false, reading: null, why: 'the reader printed JSON with no subject reading in it' };
  }
  return { ok: true, reading: parsed.subject, why: null };
}
