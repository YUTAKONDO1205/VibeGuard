// VG-SMELL-041 NEGATIVE — the hop is an OBJECT, and the guard was written for a
// different field of it.
//
// ★ REDUCED FROM A MEASURED FALSE POSITIVE.
// `paper_data/corpus1k/JimLiu__baoyu-skills/scripts/publish-skill.mjs:26` reads
// an options object out of `process.argv`, opens `options.changelogFile`, and a
// few lines later validates `options.version`. Both statements mention
// `options`, so the first version's premise — "a security operation written FOR
// THIS VALUE" — was satisfied by two statements about two entirely different
// values.
//
// The cause was the boundary: `\boptions\b` matches inside `options.version`,
// because `.` satisfies a word boundary on both sides. A chain name mentioned as
// `name.property` names a PROPERTY, and this rule's premise is about a VALUE, so
// `mentionsBare` now refuses a trailing `.` — applied to the SINK's argument as
// well as to the guard's, which is the half that closes the corpus case.
//
// The two functions pin the two halves separately; neither can stand in for the
// other.
import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from './args';
import { validateOptions } from './security/options';
import { sanitizeReleaseName } from './security/release-name';

// HALF ONE — the SINK consumes a property (`options.changelogFile`) while the
// guard names the object itself. Without the bare-mention test on the sink, this
// is reported as a check that ran too late for a file it has nothing to do with.
export async function publishSkill(): Promise<string> {
  const options = parseArgs(process.argv.slice(2));
  const changelog = await fs.readFile(path.resolve(options.changelogFile), 'utf8');
  validateOptions(options);
  return changelog;
}

// HALF TWO — the SINK consumes the value (`target`) while the GUARD names a
// property of another hop on the same chain. Without the bare-mention test on
// the guard's argument, `meta.name` establishes a premise about `meta`.
export async function writeChangelog(): Promise<void> {
  const meta = parseArgs(process.argv.slice(2));
  const target = meta.outFile;
  await fs.writeFile(target, 'changelog\n');
  sanitizeReleaseName(meta.name);
}
