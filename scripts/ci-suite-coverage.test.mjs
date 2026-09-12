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

/**
 * Every Python test file under compiler/, by path.
 *
 * The directory rule above is blind to them: it keys on `.test.mjs`, so a lane
 * that adds `test/test_x.py` to a directory ci.yml already names passes it
 * while its Python never runs. That happened on 2026-09-12 --
 * compiler/eval/metamorphic/test gained 290 lines of Python that the
 * `run_suite metamorphic …/*.test.mjs` glob could not pick up -- and the
 * directory rule reported nothing, because the directory was named. Python is
 * run by explicit filename in this workflow, so the filename is what has to
 * appear.
 */
function pyTests(root, out = []) {
  let entries;
  try { entries = readdirSync(root, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(root, e.name);
    if (e.isDirectory()) {
      if (['node_modules', '_build', 'dist', '__pycache__'].includes(e.name)) continue;
      pyTests(p, out);
    } else if (/^test_.*\.py$/.test(e.name)) {
      out.push(relative(REPO, p).split(SEP).join('/'));
    }
  }
  return out;
}

describe('CI runs every suite this tree has', () => {
  const yml = readFileSync(CI, 'utf8');
  const dirs = suiteDirs(join(REPO, 'compiler'));
  const pys = pyTests(join(REPO, 'compiler'));

  it('names every Python test file by name, since Python is run by filename here', () => {
    expect(pys.length).toBeGreaterThan(0);
    expect(pys).toContain('compiler/eval/metamorphic/test/test_check_meta_survival_axis.py');
    const missing = pys.filter((f) => !yml.includes(f));
    expect(missing, `Python test files no CI job runs:\n  ${missing.join('\n  ')}`).toEqual([]);
  });

  // A step that CALLS run_suite must be the step that DEFINES it.
  //
  // Naming a suite in this file is not the same as running it, and the way the
  // two came apart on 2026-09-12 was a new step inserted in the middle of the
  // old one: the trailing `run_suite gcc-repair` line stayed where it was in
  // the text and became part of the new step's `run:` block, where the shell
  // function does not exist. That is a red step AND a suite that runs nowhere,
  // and every check in this file passed, because all of them ask what the file
  // MENTIONS. This one asks what the steps CONTAIN. No YAML parser: this repo
  // ships none, and the shape needed here is a step boundary and two strings.
  it('every step that calls run_suite also defines it', () => {
    const steps = yml.split(/\n(?=\s*- name:)/);
    const broken = [];
    for (const step of steps) {
      const body = step.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
      const calls = /(^|\n)\s+run_suite\s+\S/.test(body);
      const defines = /run_suite\s*\(\)\s*\{/.test(body);
      if (calls && !defines) broken.push((/- name:\s*(.*)/.exec(step) || [, '(unnamed step)'])[1].trim());
    }
    expect(broken, `steps calling run_suite without the function:\n  ${broken.join('\n  ')}`).toEqual([]);
  });

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
