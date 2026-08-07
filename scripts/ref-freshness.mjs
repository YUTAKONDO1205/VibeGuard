// ref-freshness — refuse to answer a question about a ref that is out of date.
//
// WHY THIS EXISTS
//
// A full audit of this repository was carried out by several people and several
// agents at once. Everyone ran the right check, everyone got a clean result, and
// everyone was wrong, because every one of them read a remote-tracking ref that
// had not been fetched in a long time. The needle was right. The plumbing was
// right. The TARGET was more than sixty commits old, and nothing in any tool's
// output said so — a stale `refs/remotes/<remote>/<branch>` looks byte-for-byte
// like a fresh one.
//
// This is the one failure a self-test cannot catch. A planted positive proves
// the instrument works; it says nothing about whether the instrument was pointed
// at today's tree. So the two checks are separate programs, and this is the one
// that answers "is what I am about to read actually what is on the remote".
//
//   node scripts/ref-freshness.mjs                        # every branch of origin
//   node scripts/ref-freshness.mjs --remote upstream
//   node scripts/ref-freshness.mjs --branch main          # repeatable
//   node scripts/ref-freshness.mjs --tags                 # include tags
//   node scripts/ref-freshness.mjs --verbose              # list every ref compared
//   node scripts/ref-freshness.mjs --allow-empty          # 0 refs is not an error
//
// Test / offline injection points. Both replace ONE side of the comparison with
// a file, so the other side is still the real thing:
//
//   --ls-remote-from <file>    lines of `<sha>\t<refname>`, as `git ls-remote` prints
//   --local-refs-from <file>   lines of `<sha> <refname>`, as `git for-each-ref` prints
//
// EXIT CODES (interfaces.md section 7; the same numbers every executable here uses)
//
//   0  in sync — and only then is `FRESHNESS: IN_SYNC` printed
//   1  the tool failed (no git, `ls-remote` could not reach the remote)
//   3  the answer is not available: refs diverge, nothing was compared, or a
//      line of plumbing output could not be parsed
//
// Divergence is 3 and not 2 on purpose. A finding is a fact about the tree. A
// stale ref is the absence of a fact: it means no statement about the tree can
// be made yet, which is exactly what code 3 is reserved for. Conflating it with
// 0 is the bug this file exists to prevent; conflating it with 2 would tell an
// operator to go fix a leak that may not exist.
//
// ON PARSE FAILURES BEING FATAL
//
// A malformed line is never skipped. Two of this repository's silent breakages
// were a layer quietly dropping input — a path converter that ate a leading
// slash, a here-doc that ate a level of backslash — and in both cases the
// visible symptom was a smaller input set and a confident clean answer. A
// dropped line here would mean a ref that silently stopped being compared, so
// an unparseable line stops the run.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Duplicated from the driver's exit module rather than imported: scripts/ is
// outside the npm workspaces and outside that toolchain's build, and a runtime
// import would make this script fail on a checkout where the toolchain was never
// set up. scripts/ref-freshness.test.ts pins these values to
// compiler/driver/lib/exit.mjs by reading both as text, so the copy cannot drift
// without a red test.
export const EXIT_OK = 0;
export const EXIT_TOOL_FAILED = 1;
export const EXIT_FINDINGS = 2;
export const EXIT_INCOMPLETE = 3;
export const EXIT_INTEGRITY = 4;

/** Ref-comparison states. `IN_SYNC` is the only one that permits an answer. */
export const IN_SYNC = 'IN_SYNC';
export const DIVERGED = 'DIVERGED';
export const MISSING_LOCALLY = 'MISSING_LOCALLY'; // on the remote, no tracking ref here
export const STALE_LOCALLY = 'STALE_LOCALLY'; // tracking ref here, deleted on the remote

// ── Parsing ─────────────────────────────────────────────────────────────────

/**
 * `git ls-remote` output: `<sha>\t<refname>` per line.
 *
 * Peeled annotated-tag lines (`refs/tags/x^{}`) are dropped deliberately and
 * NOT counted as malformed: `git for-each-ref`'s `%(objectname)` for a local tag
 * is the tag object, which is what the unpeeled line carries. Comparing against
 * the peeled line would report every annotated tag as diverged forever.
 */
export function parseLsRemote(text) {
  const refs = new Map();
  const malformed = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '') continue;
    const m = /^([0-9a-f]{40}|[0-9a-f]{64})\s+(\S+)$/.exec(line);
    if (m === null) {
      malformed.push(line.slice(0, 120));
      continue;
    }
    if (m[2].endsWith('^{}')) continue;
    refs.set(m[2], m[1]);
  }
  return { refs, malformed };
}

/** `git for-each-ref --format='%(objectname) %(refname)'` output. */
export function parseForEachRef(text) {
  const refs = new Map();
  const malformed = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '') continue;
    const m = /^([0-9a-f]{40}|[0-9a-f]{64})\s+(\S+)$/.exec(line);
    if (m === null) {
      malformed.push(line.slice(0, 120));
      continue;
    }
    refs.set(m[2], m[1]);
  }
  return { refs, malformed };
}

/**
 * Both sides expressed in one namespace, so `refs/heads/x` on the remote and
 * `refs/remotes/<remote>/x` here are the same row.
 *
 * Returns null for a ref that has no counterpart concept — the symbolic
 * `refs/remotes/<remote>/HEAD`, or anything outside heads/tags. Those become
 * SKIPPED and are named in the output; they are never silently dropped.
 */
export function logicalKey(refname, remote) {
  if (refname === `refs/remotes/${remote}/HEAD`) return null;
  if (refname.startsWith('refs/heads/')) return `heads/${refname.slice('refs/heads/'.length)}`;
  const remotePrefix = `refs/remotes/${remote}/`;
  if (refname.startsWith(remotePrefix)) return `heads/${refname.slice(remotePrefix.length)}`;
  if (refname.startsWith('refs/tags/')) return `tags/${refname.slice('refs/tags/'.length)}`;
  return null;
}

// ── Comparison ──────────────────────────────────────────────────────────────

/**
 * Pure. Takes both sides already parsed and returns one row per logical ref.
 *
 * `branches` narrows to named branches when non-empty; `includeTags` decides
 * whether tags participate at all. Everything excluded by either is returned in
 * `skipped` WITH ITS NAME — a count on its own is how a filter that silently ate
 * the branch you cared about goes unnoticed.
 */
export function compareRefs({ remote, remoteRefs, localRefs, branches = [], includeTags = false }) {
  const wanted = new Set(branches);
  const remoteByKey = new Map();
  const localByKey = new Map();
  const skipped = [];

  for (const [name, sha] of remoteRefs) {
    const key = logicalKey(name, remote);
    if (key === null) {
      skipped.push([name, 'not a head or tag']);
      continue;
    }
    remoteByKey.set(key, sha);
  }
  for (const [name, sha] of localRefs) {
    const key = logicalKey(name, remote);
    if (key === null) {
      skipped.push([name, 'symbolic or out of namespace']);
      continue;
    }
    localByKey.set(key, sha);
  }

  const keys = [...new Set([...remoteByKey.keys(), ...localByKey.keys()])].sort();
  const rows = [];
  for (const key of keys) {
    if (!includeTags && key.startsWith('tags/')) {
      skipped.push([key, 'tag (pass --tags to include)']);
      continue;
    }
    if (wanted.size > 0 && !wanted.has(key.replace(/^heads\//, ''))) {
      skipped.push([key, 'not named by --branch']);
      continue;
    }
    const r = remoteByKey.get(key) ?? null;
    const l = localByKey.get(key) ?? null;
    let state;
    if (r !== null && l !== null) state = r === l ? IN_SYNC : DIVERGED;
    else if (r !== null) state = MISSING_LOCALLY;
    else state = STALE_LOCALLY;
    rows.push({ key, state, remote: r, local: l });
  }

  return {
    rows,
    skipped,
    inputs: rows.length + skipped.length,
    checked: rows.length,
  };
}

/** Rows that make an answer impossible. */
export function divergentRows(rows) {
  return rows.filter((r) => r.state !== IN_SYNC);
}

// ── git plumbing ────────────────────────────────────────────────────────────

function git(args, opts = {}) {
  return execFileSync('git', args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
}

/**
 * How far behind the local ref is, when that can be established WITHOUT a
 * network round trip. Returns null when the remote object is not in the local
 * object store, which is the common case for a ref nobody has fetched — and the
 * distinction matters: "60 commits behind" and "distance NOT_OBSERVED" are
 * different claims and merging them would be the same mistake this file is about.
 */
function distance(localSha, remoteSha) {
  for (const sha of [localSha, remoteSha]) {
    if (sha === null) return null;
    try {
      git(['cat-file', '-e', `${sha}^{commit}`], { stdio: 'ignore' });
    } catch {
      return null;
    }
  }
  try {
    const behind = Number.parseInt(git(['rev-list', '--count', `${localSha}..${remoteSha}`]).trim(), 10);
    const ahead = Number.parseInt(git(['rev-list', '--count', `${remoteSha}..${localSha}`]).trim(), 10);
    if (!Number.isFinite(behind) || !Number.isFinite(ahead)) return null;
    return { behind, ahead };
  } catch {
    return null;
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

function flagValue(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 || i + 1 >= argv.length ? null : argv[i + 1];
}

function flagValues(argv, name) {
  const out = [];
  for (let i = 0; i < argv.length; i += 1) if (argv[i] === name && i + 1 < argv.length) out.push(argv[i + 1]);
  return out;
}

export function main(argv) {
  const remote = flagValue(argv, '--remote') ?? 'origin';
  const branches = flagValues(argv, '--branch');
  const includeTags = argv.includes('--tags');
  const verbose = argv.includes('--verbose');
  const allowEmpty = argv.includes('--allow-empty');
  const lsRemoteFrom = flagValue(argv, '--ls-remote-from');
  const localRefsFrom = flagValue(argv, '--local-refs-from');

  const injected = [];
  let remoteText;
  let localText;

  try {
    if (lsRemoteFrom !== null) {
      remoteText = readFileSync(resolve(lsRemoteFrom), 'utf8');
      injected.push(`remote side read from ${lsRemoteFrom} (--ls-remote-from)`);
    } else {
      const configured = git(['remote']).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (!configured.includes(remote)) {
        console.error(`no remote named '${remote}' is configured (found: ${configured.join(', ') || 'none'}).`);
        console.error('Freshness is NOT_OBSERVED. Refusing to say the local refs are current.');
        return EXIT_INCOMPLETE;
      }
      const args = includeTags ? ['ls-remote', '--heads', '--tags', remote] : ['ls-remote', '--heads', remote];
      remoteText = git(args, { timeout: 120_000 });
    }
  } catch (err) {
    const e = /** @type {{ stderr?: string; message?: string }} */ (err);
    console.error(`could not read the remote side: ${(e.stderr ?? e.message ?? '').toString().trim()}`);
    console.error('');
    console.error('This is a TOOL FAILURE, not a clean result. Freshness is NOT_OBSERVED and no');
    console.error('statement about the local refs follows from it.');
    return EXIT_TOOL_FAILED;
  }

  try {
    if (localRefsFrom !== null) {
      localText = readFileSync(resolve(localRefsFrom), 'utf8');
      injected.push(`local side read from ${localRefsFrom} (--local-refs-from)`);
    } else {
      const scope = includeTags ? [`refs/remotes/${remote}`, 'refs/tags'] : [`refs/remotes/${remote}`];
      localText = git(['for-each-ref', '--format=%(objectname) %(refname)', ...scope]);
    }
  } catch (err) {
    const e = /** @type {{ stderr?: string; message?: string }} */ (err);
    console.error(`could not read the local remote-tracking refs: ${(e.stderr ?? e.message ?? '').toString().trim()}`);
    return EXIT_TOOL_FAILED;
  }

  const remoteParsed = parseLsRemote(remoteText);
  const localParsed = parseForEachRef(localText);
  const malformed = [
    ...remoteParsed.malformed.map((l) => ['remote', l]),
    ...localParsed.malformed.map((l) => ['local', l]),
  ];
  if (malformed.length > 0) {
    for (const [side, line] of malformed) console.error(`UNPARSEABLE ${side} line: ${JSON.stringify(line)}`);
    console.error('');
    console.error(`${malformed.length} line(s) of ref plumbing could not be parsed. They are NOT skipped:`);
    console.error('a dropped line is a ref that quietly stopped being compared, which is how a');
    console.error('confident "in sync" gets printed about a set that shrank without anyone noticing.');
    return EXIT_INCOMPLETE;
  }

  const result = compareRefs({
    remote,
    remoteRefs: remoteParsed.refs,
    localRefs: localParsed.refs,
    branches,
    includeTags,
  });

  for (const note of injected) console.log(`INJECTED: ${note}`);
  console.log(`remote:   ${remote}`);
  console.log(`inputs=${result.inputs} checked=${result.checked} skipped=${result.skipped.length}`);
  // Two classes of skip, printed differently on purpose. A ref excluded by a
  // filter the operator typed is not news; a ref excluded because this program
  // did not recognise its namespace IS news, because that is what a silently
  // shrinking input set looks like from the outside. The first class is
  // summarised with the flag that caused it and listed under --verbose; the
  // second is always named, however long the list gets.
  const byFilter = result.skipped.filter(([, why]) => why.startsWith('tag') || why.startsWith('not named'));
  const unrecognised = result.skipped.filter(([, why]) => !(why.startsWith('tag') || why.startsWith('not named')));
  for (const [name, why] of unrecognised) console.log(`  skipped ${name} — ${why}`);
  if (byFilter.length > 0) {
    console.log(`  skipped ${byFilter.length} ref(s) excluded by a filter you passed${verbose ? ':' : ' (--verbose lists them)'}`);
    if (verbose) for (const [name, why] of byFilter) console.log(`    ${name} — ${why}`);
  }
  if (verbose) for (const r of result.rows) console.log(`  ${r.state.padEnd(16)} ${r.key}`);

  if (result.checked === 0) {
    if (!allowEmpty) {
      console.error('');
      console.error('Nothing was compared. An empty comparison is vacuously "in sync", which is the');
      console.error('shape of every false clean result this check exists to prevent. Pass');
      console.error('--allow-empty if a repository with no matching refs is genuinely expected.');
      return EXIT_INCOMPLETE;
    }
    console.log('');
    console.log('0 refs compared, and --allow-empty was passed. Freshness is NOT_OBSERVED.');
    return EXIT_OK;
  }

  const bad = divergentRows(result.rows);
  if (bad.length > 0) {
    console.log('');
    console.log(`${bad.length} of ${result.checked} ref(s) differ between ${remote} and the local tracking refs:`);
    for (const r of bad) {
      const l = r.local === null ? '(absent)' : r.local.slice(0, 12);
      const rem = r.remote === null ? '(absent)' : r.remote.slice(0, 12);
      let note = '';
      if (r.state === DIVERGED) {
        const d = distance(r.local, r.remote);
        note = d === null
          ? '  distance NOT_OBSERVED (the remote object is not in the local store — run git fetch)'
          : `  local is ${d.behind} commit(s) behind and ${d.ahead} ahead`;
      }
      console.log(`  ${r.state.padEnd(16)} ${r.key}`);
      console.log(`      local=${l}  remote=${rem}${note}`);
    }
    console.log('');
    console.log('Reporting the divergence instead of an answer. Run `git fetch --prune ' + remote + '`');
    console.log('and re-run. A check against a ref this far from the remote describes a tree that');
    console.log('no longer exists, and it describes it in exactly the same words as a correct one.');
    return EXIT_INCOMPLETE;
  }

  console.log('');
  console.log(`FRESHNESS: ${IN_SYNC} — ${result.checked} ref(s) match ${remote} exactly`);
  return EXIT_OK;
}

const invokedDirectly =
  process.argv[1] != null && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedDirectly) process.exit(main(process.argv.slice(2)));
