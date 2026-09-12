// Every test directory under compiler/ is named in .github/workflows/ci.yml.
//
// WHY
//
// ci.yml carries 19 hand-maintained `run_suite` lines. A lane that adds a
// `test/` directory and forgets one gets a green tick from a job that never ran
// its tests, and nothing anywhere says so: the lane's own suite passes locally,
// CI passes, and the only evidence is a line missing from a YAML file nobody
// diffs. `compiler/eval/oracle-agreement` was added on 2026-09-12 with 109 tests
// and reached no runner until somebody went looking.
//
// The instance is one line. The class is this file: the list stops being
// hand-maintained in the sense that matters, because forgetting is now a
// failing test rather than a silence.
//
// WHAT IS DELIBERATELY NOT ASSERTED: that the suite runs on every job, or on any
// particular runner. Some suites need a compiler and are confined to the
// native-toolchain jobs on purpose. The claim here is only that the directory is
// mentioned somewhere in the workflow, which is the difference between "decided
// to run it there" and "nobody noticed it existed".

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const CI = join(REPO, '.github', 'workflows', 'ci.yml');
const SEP = String.fromCharCode(92); // a backslash, written so no here-doc can eat it

/** Every directory under compiler/ that holds at least one *.test.mjs. */
function suiteDirs(root, out = []) {
  let entries;
  try { entries = readdirSync(root, { withFileTypes: true }); } catch { return out; }
  let hasTests = false;
  for (const e of entries) {
    const p = join(root, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '_build' || e.name === 'dist') continue;
      suiteDirs(p, out);
    } else if (e.name.endsWith('.test.mjs')) {
      hasTests = true;
    }
  }
  // posix separators, whatever this machine uses
  if (hasTests) out.push(relative(REPO, root).split(SEP).join('/'));
  return out;
}

describe('CI runs every suite this tree has', () => {
  const yml = readFileSync(CI, 'utf8');
  const dirs = suiteDirs(join(REPO, 'compiler'));

  it('found some suites, so this file is not asserting over an empty set', () => {
    expect(dirs.length).toBeGreaterThan(10);
    expect(dirs).toContain('compiler/eval/oracle-agreement/test');
  });

  it('names every one of them', () => {
    const missing = dirs.filter((d) => !yml.includes(d.replace(/\/test$/, '')));
    expect(missing, `test directories no CI job mentions:\n  ${missing.join('\n  ')}`).toEqual([]);
  });

  it('the run_suite list is not empty and every entry points at something that exists', () => {
    const named = [...yml.matchAll(/run_suite\s+\S+\s+(\S+)/g)].map((m) => m[1]);
    expect(named.length).toBeGreaterThan(15);
    for (const glob of named) {
      const dir = join(REPO, dirname(glob));
      expect(() => statSync(dir), `${glob} names a directory that does not exist`).not.toThrow();
    }
  });
});
