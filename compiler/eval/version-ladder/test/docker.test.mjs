/**
 * The docker rung, and the refusal that stands in for it on a machine with no
 * daemon -- which is every machine this lane has run on.
 *
 * WHY THIS FILE EXISTS. The lane's README and its report writer both said, in a
 * sentence nothing measured, that the docker daemon was not reachable and the
 * distro had no docker CLI. The report writer said it as a LITERAL -- printed on
 * every run, on every machine, whether or not it was true -- and `--write-data`
 * copied it into a tracked record. Half of it was already wrong when it was
 * written: a CLI is present on this machine and answers `--version`; what is
 * absent is the daemon behind it. That is the defect shape this lane has had to
 * fix once already in its own anchor: prose asserting a state where a
 * measurement belongs.
 *
 * So the refusal is now a reading, and every test below is a test that the
 * reading can change. The daemon cannot be started from here, which is exactly
 * why these cases are pure: the probe RESULTS go in, the refusal comes out, and
 * "the daemon appeared" is a case this file can exercise on a box that has none.
 *
 * The second thing under test is the one that costs money if it is wrong: THE
 * LANE MUST NEVER FETCH. `docker run` on a missing image pulls by default, and a
 * rung named at a prompt would become several gigabytes off a network in a tree
 * whose stated rule (compiler/schema/interfaces.md section 1) is that nothing
 * fetches. The flag is asserted in the argv, and the lane's own source is
 * scanned for a pull that is not the refusal.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DOCKER_LADDER, DOCKER_LADDER_NAME, DIGEST_RE, dockerRungs, isDockerRung, dockerRung,
  digestProblem, imageRef, pinsProblem, cliProbeArgv, daemonProbeArgv, imageInspectArgv,
  dockerRunArgv, safeDetail, dockerStatus, rungProblem, dockerCounting, crossDistro,
  dockerReportLines, detailPathHits, neverFetchProblem, assertNeverFetches,
  undeclaredDockerCcProblem, CROSS_EXIT,
} from '../lib/docker.mjs';
import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import {
  allRungs, nativeRungs, dockerProbeWanted, dockerSections, ladderExit, ladderRow,
} from '../run-version-ladder.mjs';
import { anchorIndex, anchorDisagreements, anchorProblem } from '../lib/anchor.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const RUNNER = join(LANE, 'run-version-ladder.mjs');

/** A digest that is well-formed and names nothing. Every test that needs one uses this. */
const FAKE = `sha256:${'a'.repeat(64)}`;
const REF = `gcc@${FAKE}`;

// ------------------------------------------------------- the declared rung ---

test('a docker rung is declared by repository and tag, and NEVER by a digest written in the tree', () => {
  // The digest is evidence, not a declaration: it can only come from a registry,
  // and one written here that nobody on this machine ever resolved would be a
  // fabricated measurement in a tracked file. The pins file is where it lives.
  assert.ok(DOCKER_LADDER.length >= 2, 'a ladder needs more than one rung');
  const seen = [];
  for (const r of DOCKER_LADDER) {
    assert.equal(r.cc, `${DOCKER_LADDER_NAME}-${r.major}`);
    assert.equal(r.ladder, DOCKER_LADDER_NAME);
    assert.ok(r.repository && !r.repository.includes('@'), `${r.cc} has no repository`);
    assert.equal(r.tag, String(r.major));
    assert.ok(r.program, `${r.cc} does not name the compiler inside the image`);
    assert.equal(r.nativeCc, `${r.nativeVendor}-${r.major}`);
    assert.ok(!Object.prototype.hasOwnProperty.call(r, 'digest'), `${r.cc} declares a digest`);
    seen.push(r.major);
  }
  assert.deepEqual([...seen].sort((a, b) => a - b), seen, 'rungs must be lowest first');
  assert.equal(readFileSync(join(LANE, 'lib/docker.mjs'), 'utf8').includes('sha256:'), true,
    'the digest FORM is named here');
  assert.equal(/sha256:[0-9a-f]{64}/.test(readFileSync(join(LANE, 'lib/docker.mjs'), 'utf8')), false,
    'no concrete digest may be written into this file: it would be a measurement nobody took');
});

test('the docker rungs are enumerated beside the apt rungs, and are not a default', () => {
  // Both halves matter. In allRungs() because that is what decides the run's
  // denominator -- a rung absent from it is a rung nobody can see was not
  // obtained. Out of the default --ccs because obtaining one needs an image
  // somebody pulled, and a default run that refused on every machine would cost
  // the apt ladder that CAN be measured.
  for (const cc of dockerRungs()) {
    assert.ok(allRungs().includes(cc), `${cc} is not enumerated`);
    assert.ok(!nativeRungs().includes(cc), `${cc} must not be a default rung`);
    assert.ok(isDockerRung(cc));
    assert.equal(dockerRung(cc).major, Number(cc.split('-').pop()));
  }
  assert.equal(allRungs().length, nativeRungs().length + dockerRungs().length);
  assert.equal(isDockerRung('gcc-13'), false);
  assert.equal(dockerRung('gcc-13'), null);
});

// ------------------------------------------------------------ the identity ---

test('a tag is not a rung: only a sha256 digest identifies one', () => {
  assert.match(digestProblem('docker-gcc-13', null), /no digest is pinned/);
  assert.match(digestProblem('docker-gcc-13', ''), /no digest is pinned/);
  assert.match(digestProblem('docker-gcc-13', '13'), /not a digest/);
  assert.match(digestProblem('docker-gcc-13', 'sha256:abc'), /not a digest/);
  assert.match(digestProblem('docker-gcc-13', `sha256:${'A'.repeat(64)}`), /not a digest/, 'hex is lower case');
  assert.equal(digestProblem('docker-gcc-13', FAKE), null);
  assert.ok(DIGEST_RE.test(FAKE));
});

test('imageRef is repository@digest, and refuses to build one out of a tag', () => {
  assert.equal(imageRef(dockerRung('docker-gcc-13'), FAKE), REF);
  assert.throws(() => imageRef(dockerRung('docker-gcc-13'), '13'), /not a digest/);
  assert.throws(() => imageRef(null, FAKE), /not a declared docker rung/);
});

test('a pins file may pin a declared rung and may not introduce one', () => {
  assert.equal(pinsProblem(null), null);
  assert.equal(pinsProblem({ 'docker-gcc-13': FAKE }), null);
  assert.match(pinsProblem({ 'docker-gcc-99': FAKE }), /not a declared docker rung/);
  assert.match(pinsProblem({ 'gcc-13': FAKE }), /not a declared docker rung/);
  assert.match(pinsProblem({ 'docker-gcc-13': '13' }), /not a digest/);
  assert.match(pinsProblem([]), /JSON object/);
  assert.match(pinsProblem('x'), /JSON object/);
});

// ------------------------------------------------------- THE LANE NEVER FETCHES

test('every docker invocation carries --pull=never, so a missing image is a refusal and not a download', () => {
  const argv = dockerRunArgv({ ref: REF, program: 'gcc', args: ['-O2', '-o', 'a.s', 'a.c'], hostDir: '/tmp/x' });
  assert.ok(argv.includes('--pull=never'), argv.join(' '));
  assert.ok(argv.includes('--network=none'), 'the compile may not reach a network either');
  assert.equal(argv[0], 'run');
  assert.ok(!argv.includes('pull'), 'no pull subcommand anywhere in the invocation');
  // the image is named by digest and the compiler arguments are basenames, so no
  // host path can reach a record composed out of this line
  assert.ok(argv.includes(REF));
  assert.deepEqual(argv.slice(argv.indexOf(REF)), [REF, 'gcc', '-O2', '-o', 'a.s', 'a.c']);
  assert.throws(() => dockerRunArgv({ ref: 'gcc:13', program: 'gcc', hostDir: '/tmp/x' }), /not a digest-pinned/);
  assert.throws(() => dockerRunArgv({ ref: REF, program: 'gcc' }), /no host directory/);
});

test('the image probe READS the local store and cannot fetch', () => {
  assert.deepEqual(imageInspectArgv(REF), ['image', 'inspect', '--format', '{{.Id}}', REF]);
  assert.deepEqual(cliProbeArgv(), ['--version']);
  assert.deepEqual(daemonProbeArgv(), ['info', '--format', '{{.ServerVersion}}']);
  for (const argv of [imageInspectArgv(REF), cliProbeArgv(), daemonProbeArgv()]) {
    assert.ok(!argv.includes('pull'), argv.join(' '));
  }
});

test('THE CONTRACT IS STRUCTURAL: an invocation that could fetch is refused, whoever composed it', () => {
  // Defect 3. The contract used to be a grep for `--pull=never` in one file,
  // which cannot see the thing most likely to break it: a SECOND composer added
  // later. `docker run` pulls a missing image unless told not to -- the flag's
  // own default is `missing` -- so a plausible-looking argv built anywhere else
  // would have grepped clean and pulled a gigabyte. Now every argv goes through
  // one gate, and the gate refuses by default.
  //
  // THE CASE THAT FAILED BEFORE AND PASSES NOW: the composer that forgot.
  assert.match(neverFetchProblem(['run', '--rm', '-v', '/x:/vg', REF, 'gcc', '-c', 'a.c']),
    /carries no --pull=never/, 'a run with no --pull=never is the default that FETCHES');
  assert.throws(() => assertNeverFetches(['run', '--rm', REF, 'gcc']), /never fetches/);

  // the fetching spellings, including the one the README tells a person to use
  assert.match(neverFetchProblem(['pull', 'gcc:13']), /this lane runs only/);
  assert.match(neverFetchProblem(['image', 'pull', 'gcc:13']), /image inspect/);
  assert.match(neverFetchProblem(['run', '--pull=missing', '--network=none', REF, 'gcc']), /--pull=missing/);
  assert.match(neverFetchProblem(['run', '--pull', 'always', '--network=none', REF, 'gcc']), /--pull=always/);
  assert.match(neverFetchProblem(['run', '--rm', '--pull=never', 'pull', REF, 'gcc']), /`pull` appears as argv/);
  // and a subcommand NOBODY LISTED is refused too -- that is the half a needle
  // list cannot do, because a needle list only holds the spellings somebody
  // thought of
  assert.match(neverFetchProblem(['buildx', 'build', '.']), /this lane runs only/);
  assert.match(neverFetchProblem(['compose', 'up']), /this lane runs only/);
  assert.equal(neverFetchProblem(['create', '--pull=never', '--network=none', REF]), null,
    'create is allowed only when it carries the same two flags run does');
  assert.match(neverFetchProblem(['create', '--network=none', REF]), /carries no --pull=never/);
  assert.match(neverFetchProblem([]), /non-empty argv/);

  // the four the lane actually runs all pass the gate
  for (const argv of [cliProbeArgv(), daemonProbeArgv(), imageInspectArgv(REF),
    dockerRunArgv({ ref: REF, program: 'gcc', args: ['-O2'], hostDir: '/tmp/x' })]) {
    assert.equal(neverFetchProblem(argv), null, argv.join(' '));
  }
  // a compiler argument that happens to spell a docker word is not a docker
  // word: only docker's own arguments, up to the image reference, are read
  assert.equal(neverFetchProblem(dockerRunArgv({
    ref: REF, program: 'gcc', args: ['-o', 'pull.s', 'pull.c'], hostDir: '/tmp/x',
  })), null);
});

test('the gate is what the composers are held to, so deleting a flag from one is a throw and not a silent fetch', () => {
  // dockerRunArgv composes the flags AND passes the result through the gate, so
  // the guarantee survives an edit to the composer. This is the mutation the
  // old grep could not catch, done from outside: an argv identical to the real
  // one minus the flag.
  const good = dockerRunArgv({ ref: REF, program: 'gcc', args: ['-O2'], hostDir: '/tmp/x' });
  const without = good.filter((x) => x !== '--pull=never');
  assert.equal(neverFetchProblem(good), null);
  assert.match(neverFetchProblem(without), /carries no --pull=never/);
  const unnetworked = good.filter((x) => x !== '--network=none');
  assert.match(neverFetchProblem(unnetworked), /--network=none/);
});

test('no source file of this lane can start a pull', () => {
  // The gate above is the contract; this is the backstop, and it is worth
  // keeping for what the gate cannot see -- a `docker pull` written in a shell
  // script or a tool that never goes through the composer at all.
  const files = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      // data/ is a record and test/ is where the needles themselves are written
      if (e.name === 'data' || e.name === 'test' || e.name === 'node_modules') continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(mjs|js|sh)$/.test(e.name)) files.push(p);
    }
  };
  walk(LANE);
  assert.ok(files.length >= 3, `only ${files.length} source files found; the scan is looking in the wrong place`);

  // THE NEEDLES, AND THEIR POSITIVE CONTROL. Three needles reporting zero prove
  // nothing unless each can be shown to fire, and the previous version of this
  // scan had no control at all -- plus it MISSED `docker image pull`, which is
  // the exact spelling this lane's own README tells a person to use. Each needle
  // is run against a text that must match before any file is scanned: a needle
  // that cannot fire is a needle that has stopped looking.
  const NEEDLES = [
    { re: /docker\s+(image\s+)?pull\b/, why: 'runs a docker pull', fires: 'sh -c "docker image pull gcc:13"' },
    { re: /(?:\[|\.push\(|\(\s*)['"`]pull['"`]/, why: "passes 'pull' as an argv element", fires: "run('docker', ['pull', ref])" },
    { re: /--pull(=(?!never)|['"`\s])/, why: 'sets --pull to something other than never', fires: "argv.push('--pull', 'always')" },
    { re: /\bpullPolicy\b|--pull-always|--all-tags/, why: 'carries a fetching flag', fires: 'docker run --pull-always x' },
  ];
  for (const n of NEEDLES) {
    assert.ok(n.re.test(n.fires), `the needle ${n.re} cannot fire even on ${JSON.stringify(n.fires)}`);
  }

  const scanned = [];
  const gated = [];
  // The file that IMPLEMENTS the refusal is the one file that has to spell the
  // words -- `neverFetchProblem` cannot refuse `--pull=missing` without naming
  // it. It is exempted BY NAME and it is held to something stronger instead:
  // the gate's own behaviour, tested above, and the rule below.
  const GATE = join('lib', 'docker.mjs');
  for (const f of files) {
    // CODE only. A comment is where the rule is explained, and a scan that made
    // the explanation unwritable would be read around rather than obeyed.
    const text = readFileSync(f, 'utf8')
      .split(/\r?\n/).filter((l) => !/^\s*(\*|\/\/|#)/.test(l)).join('\n');
    scanned.push(f);
    if (!f.endsWith(GATE)) for (const n of NEEDLES) assert.ok(!n.re.test(text), `${f} ${n.why}`);
    // AND THE RULE THE NEEDLES CANNOT EXPRESS: a file that spawns docker at all
    // has to put its argv through the gate. This is what makes a second
    // composer impossible rather than merely unspelled -- the previous scan
    // would have passed a new `run('docker', argv)` anywhere in the lane.
    if (/(?:run|execFile|execFileSync|spawn|spawnSync)\(\s*'docker'/.test(text)) {
      gated.push(f);
      assert.ok(/assertNeverFetches\(/.test(text),
        `${f} spawns docker without passing the argv through assertNeverFetches()`);
    }
  }
  // positive control for THAT needle too: it has to be able to see a spawn
  assert.ok(/(?:run|execFile|execFileSync|spawn|spawnSync)\(\s*'docker'/.test("await run('docker', argv)"));
  assert.ok(gated.length >= 1, 'no file in this lane was seen to spawn docker: the spawn needle has stopped looking');

  // AND THE SITE ITSELF, not merely the file. A file-level rule is satisfied by
  // the word appearing anywhere in it, so a spawn that skipped the gate while
  // some other function still called it would pass -- which it did: deleting the
  // gate from the spawn wrapper left this whole suite green until this was
  // added. One spawn site, and the gate is in it.
  const runnerCode = readFileSync(join(LANE, 'run-version-ladder.mjs'), 'utf8')
    .split(/\r?\n/).filter((l) => !/^\s*(\*|\/\/|#)/.test(l)).join('\n');
  const sites = [...runnerCode.matchAll(/\brun\(\s*'docker'/g)];
  assert.equal(sites.length, 1,
    `docker is spawned at ${sites.length} sites in the runner; the gate is asserted at one, so add it to the other`);
  const before = runnerCode.slice(Math.max(0, sites[0].index - 300), sites[0].index);
  assert.ok(/assertNeverFetches\(\s*argv\s*\)/.test(before),
    'the one docker spawn site does not put its argv through assertNeverFetches() first');
  // positive control for both halves
  assert.equal([...("await run('docker', a); await run('docker', b)").matchAll(/\brun\(\s*'docker'/g)].length, 2);
  assert.ok(!/assertNeverFetches\(\s*argv\s*\)/.test('return run(argv);'));

  // The scan must have read the file the invocation is composed in AND the file
  // that spawns it. The old version asserted `scanned === files.length`, which
  // is true however few files the walk found -- a tautology, and the one thing
  // that could have made the whole scan vacuous.
  const mustScan = ['lib/docker.mjs', 'run-version-ladder.mjs', 'tools/fortify-spelling-probe.mjs'];
  for (const name of mustScan) {
    assert.ok(scanned.some((f) => f.endsWith(name.split('/').join(sep)) || f.endsWith(name)),
      `${name} was not scanned; the walk is looking in the wrong place`);
  }
  assert.ok(scanned.length >= mustScan.length, `${scanned.length} files scanned`);
});

// -------------------------------------------------------------- the reading --

test('dockerStatus names WHICH probe failed, and stops saying so when it answers', () => {
  const noCli = dockerStatus({ cli: { ok: false, detail: 'ENOENT' } });
  assert.equal(noCli.reachable, false);
  assert.equal(noCli.failedProbe, 'docker --version');
  assert.match(noCli.reason, /no docker CLI answered/);

  // This machine's actual state, and the half the old literal got wrong: a CLI
  // IS present and answers --version; what is missing is the daemon behind it.
  const noDaemon = dockerStatus({ cli: { ok: true, detail: 'Docker version 99' }, daemon: { ok: false, detail: 'cannot connect' } });
  assert.equal(noDaemon.reachable, false);
  assert.equal(noDaemon.failedProbe, 'docker info');
  assert.match(noDaemon.reason, /a docker CLI answered but no daemon did/);
  assert.equal(noDaemon.cliVersion, 'Docker version 99');

  const up = dockerStatus({ cli: { ok: true, detail: 'Docker version 99' }, daemon: { ok: true, detail: '27.1.1' } });
  assert.equal(up.reachable, true);
  assert.equal(up.failedProbe, null);
  assert.equal(up.reason, null);
  assert.equal(up.serverVersion, '27.1.1');

  // a probe that was never run is never a pass
  assert.equal(dockerStatus({}).reachable, false);
  assert.match(dockerStatus({ cli: { ok: true, detail: 'x' } }).reason, /never probed/);

  // NOT PROBED is its own state, and it is NOT a failed probe. The runner spends
  // the two subprocesses only when a docker rung was requested, so the common
  // case is that nothing was attempted -- and naming `docker --version` as the
  // probe that "failed on this machine" would be an assertion about a command
  // nobody ran, which is the literal this whole file replaced wearing a
  // measurement's clothes.
  const unprobed = dockerStatus({});
  assert.equal(unprobed.probed, false);
  assert.equal(unprobed.failedProbe, null, 'nothing failed: nothing ran');
  assert.match(unprobed.reason, /nothing was probed/);
  for (const s of [noCli, noDaemon, up]) assert.equal(s.probed, true, 'a probe that ran says so');
});

test('a run that asked for no docker rung says NOT PROBED, and never names a probe as failed', () => {
  // Defect 8, in the report rather than in the status. `probeDocker()` runs two
  // subprocesses with 20s and 30s timeouts and the second OPENS THE DAEMON
  // SOCKET; it used to run on every invocation of this lane, including the
  // default apt-only one and every spawn in this suite. Making it conditional is
  // only safe if the report can say so, which is what this pins.
  const L = dockerReportLines({ status: dockerStatus({}) }).join('\n');
  assert.match(L, /NOT PROBED/);
  assert.match(L, /asked for no docker rung/);
  assert.doesNotMatch(L, /MEASURED, not assumed/);
  assert.doesNotMatch(L, /failed on this machine/);
  // and the runner only probes when a rung was asked for
  assert.equal(dockerProbeWanted(['gcc-13', 'clang-18']), false);
  assert.equal(dockerProbeWanted([]), false);
  assert.equal(dockerProbeWanted(['gcc-13', 'docker-gcc-13']), true);
});

test('a daemon error that quotes a path is redacted rather than published', () => {
  // The runner refuses to write any text carrying an absolute-path marker (exit
  // 5). A daemon is entitled to quote one, and an unredacted detail would turn
  // "docker is not running" into a failed run with a puzzling reason.
  const d = safeDetail('cannot connect to /home/someone/.docker/run/docker.sock');
  assert.match(d, /detail withheld/);
  assert.ok(!d.includes('someone'));
  assert.equal(safeDetail('cannot connect to the daemon'), 'cannot connect to the daemon');
  assert.equal(safeDetail(null), '');
});

test('THE CANONICAL DAEMON REFUSAL is redacted -- it carries no marker the shared scan looks for', () => {
  // Defect 4, and it is the detail this lane is most likely to ever see. The
  // shared provenance scan (repair-loop/lib/provenance.mjs) looks for `/home/`,
  // `/root/`, `/mnt/`, `/Users/` and a drive letter, because it is about a
  // MEASUREMENT carrying the measuring machine's layout. The canonical Linux
  // refusal carries none of them:
  const linux = 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?';
  assert.deepEqual(absolutePathHits(linux), [], 'the shared scan is blind to this, which is why the lane has its own');
  const redacted = safeDetail(linux);
  assert.match(redacted, /detail withheld/);
  // the marker NAMES are kept -- they are generic and they are what a reader
  // needs to know why the text is gone -- and everything around them is dropped
  assert.ok(!redacted.includes('docker.sock'), redacted);
  assert.ok(!redacted.includes('Cannot connect to the Docker daemon at'), redacted);
  assert.ok(redacted.includes('unix://'), 'the reader is told WHICH marker withheld it');

  // and the Windows spelling, which is what this machine actually answers
  const win = 'error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.';
  assert.match(safeDetail(win), /detail withheld/);
  assert.ok(!safeDetail(win).includes('dockerDesktopLinuxEngine'), safeDetail(win));

  // detailPathHits NAMES the marker and never the text around it -- the whole
  // point of reporting a marker rather than the string
  const hits = detailPathHits(linux);
  assert.ok(hits.includes('unix://') && hits.includes('/var/run/'), hits.join(','));
  assert.ok(!hits.join(' ').includes('docker.sock'));

  // a detail with nothing path-ish in it is published in full, or the redaction
  // would be a blanket and would tell a reader nothing
  assert.equal(detailPathHits('cannot connect to the daemon').length, 0);
  assert.equal(safeDetail('Docker version 27.1.1, build cc13f95'), 'Docker version 27.1.1, build cc13f95');
});

test('rungProblem refuses in probe order, and every refusal names the command that failed', () => {
  const down = dockerStatus({ cli: { ok: true, detail: 'v' }, daemon: { ok: false, detail: 'no daemon' } });
  const up = dockerStatus({ cli: { ok: true, detail: 'v' }, daemon: { ok: true, detail: '27' } });

  // an unpinned rung is refused before the daemon is blamed for anything
  assert.match(rungProblem({ cc: 'docker-gcc-13', digest: null, status: down }), /no digest is pinned/);
  // the daemon, named by its probe
  assert.match(rungProblem({ cc: 'docker-gcc-13', digest: FAKE, status: down }), /`docker info`/);
  assert.match(rungProblem({ cc: 'docker-gcc-13', digest: FAKE, status: down }), /it was not obtained/);
  // a missing image: the refusal, and the promise that it was NOT fetched
  const missing = rungProblem({ cc: 'docker-gcc-13', digest: FAKE, status: up, image: { ok: false, detail: 'No such image' } });
  assert.match(missing, /docker image inspect gcc@sha256:/);
  assert.match(missing, /--pull=never/);
  assert.match(missing, /pull it yourself/);
  // an image that was never probed is not a pass
  assert.match(rungProblem({ cc: 'docker-gcc-13', digest: FAKE, status: up, image: null }), /never probed/);
  // and the one state that lets the rung through
  assert.equal(rungProblem({ cc: 'docker-gcc-13', digest: FAKE, status: up, image: { ok: true, detail: 'sha256:x' } }), null);
  assert.match(rungProblem({ cc: 'gcc-13', digest: FAKE, status: up }), /not a declared docker rung/);
});

// ------------------------------------------------------------- the counting --

test('dockerCounting accounts for every declared docker rung, and a skip with no reason breaks it', () => {
  const none = dockerCounting(dockerRungs().map((cc) => ({ cc, obtained: false, reason: 'not-requested' })));
  assert.equal(none.declared, DOCKER_LADDER.length);
  assert.equal(none.obtained, 0);
  assert.equal(none.skipped, DOCKER_LADDER.length);
  assert.equal(none.accountedFor, true);

  const v = dockerRungs().map((cc) => ({ cc, obtained: false, reason: 'not-requested' }));
  v[0] = { cc: v[0].cc, obtained: false };
  assert.equal(dockerCounting(v).accountedFor, false, 'a skipped rung with no reason must not read as accounted');

  // the apt versions in the same array are not this ladder's business
  const mixed = [...dockerRungs().map((cc) => ({ cc, obtained: false, reason: 'not-requested' })),
    { cc: 'gcc-13', obtained: true }];
  assert.equal(dockerCounting(mixed).declared, DOCKER_LADDER.length);
  assert.equal(dockerCounting(mixed).obtained, 0);
  assert.equal(dockerCounting([]).accountedFor, false, 'an empty versions[] does not account for a declared ladder');
});

// ------------------------------------------------- what a docker rung is FOR --

const dRow = (id, major, opt, verdict) => ({ id, opt, major, verdict, ladder: DOCKER_LADDER_NAME, vendor: DOCKER_LADDER_NAME, cc: `docker-gcc-${major}` });
const aRow = (id, major, opt, verdict) => ({ id, opt, major, verdict, ladder: 'gcc', vendor: 'gcc', cc: `gcc-${major}` });

test('crossDistro reads the docker rung against the apt rung at the SAME major', () => {
  const rows = [
    dRow('x', 13, '-O2', 'WIPE_ELIMINATED'), aRow('x', 13, '-O2', 'WIPE_ELIMINATED'),
    dRow('y', 13, '-O2', 'WIPE_SURVIVED'), aRow('y', 13, '-O2', 'WIPE_ELIMINATED'),
  ];
  const c = crossDistro(rows);
  assert.equal(c.dockerRows, 2);
  assert.equal(c.compared, 2);
  assert.equal(c.agreed, 1);
  assert.deepEqual(c.differences, [{ id: 'y', major: 13, opt: '-O2', docker: 'WIPE_SURVIVED', apt: 'WIPE_ELIMINATED' }]);
  assert.equal(c.problem, null);
});

test('a docker rung with nothing to read it against is NOT agreement: 0 of 0 does not pass', () => {
  // The same defect the anchor already refuses, one layer up. A run that
  // obtained a container and no apt rung of the same major has established that
  // a container compiled, and nothing about any wipe.
  const c = crossDistro([dRow('x', 13, '-O2', 'WIPE_ELIMINATED'), aRow('x', 12, '-O2', 'WIPE_ELIMINATED')]);
  assert.equal(c.compared, 0);
  assert.equal(c.agreed, 0);
  assert.match(c.problem, /NONE could be compared/);
  assert.match(c.problem, /pass vacuously/);
  // and a run with no docker cell at all has no comparison to report, which is
  // a different thing from a comparison that found nothing
  assert.equal(crossDistro([aRow('x', 13, '-O2', 'WIPE_ELIMINATED')]).problem, null);
  assert.equal(crossDistro([]).problem, null);
});

test('a ladder made only of docker rungs is unanchored, and the anchor says so', () => {
  // No docker rung is an anchor rung: the tracked find-step rows are apt rows.
  // So the join finds nothing, and `checked: 0` must reach the exit as a
  // FAILURE -- the shape this lane shipped once and refuses everywhere now.
  const index = anchorIndex([{ id: 'x', kind: 'erasure', cc: 'gcc-13', opt: '-O2', verdict: 'WIPE_ELIMINATED' }]);
  const a = anchorDisagreements([dRow('x', 13, '-O2', 'WIPE_ELIMINATED')], index);
  assert.equal(a.checked, 0);
  assert.equal(a.agreed, 0);
  assert.match(anchorProblem(a), /NOT ANCHORED/);
  assert.match(anchorProblem(a), /pass vacuously/);
});

// ------------------------------------------------------------- the sentence --

test('the report sentence is derived from the probe and becomes false when the probe answers', () => {
  const down = dockerReportLines({ status: dockerStatus({ cli: { ok: true, detail: 'v' }, daemon: { ok: false, detail: 'no daemon' } }) }).join('\n');
  assert.match(down, /MEASURED, not assumed/);
  assert.match(down, /`docker info` failed on this machine/);
  assert.match(down, /becomes false the moment the probe/);
  assert.match(down, /limit on which BUILDS were reached, not a finding/);

  const up = dockerReportLines({ status: dockerStatus({ cli: { ok: true, detail: 'v' }, daemon: { ok: true, detail: '27' } }) }).join('\n');
  assert.match(up, /docker IS reachable/);
  assert.doesNotMatch(up, /MEASURED, not assumed/);
  assert.doesNotMatch(up, /produced no cell/);

  const compared = dockerReportLines({
    status: dockerStatus({ cli: { ok: true, detail: 'v' }, daemon: { ok: true, detail: '27' } }),
    requested: ['docker-gcc-13'],
    obtained: ['docker-gcc-13'],
    cross: crossDistro([dRow('x', 13, '-O2', 'WIPE_SURVIVED'), aRow('x', 13, '-O2', 'WIPE_ELIMINATED')]),
  }).join('\n');
  assert.match(compared, /cross-distribution: 0\/1 cell\(s\) agree/);
  assert.match(compared, /docker WIPE_SURVIVED, apt WIPE_ELIMINATED/);
});

test('no source file of this lane still ASSERTS the docker state as prose', () => {
  // The literal that was here printed on every run, on every machine. Its
  // replacement is dockerReportLines(), which cannot say it unless a probe did.
  for (const f of ['run-version-ladder.mjs', 'lib/docker.mjs', 'README.md']) {
    // whitespace-collapsed, because a line break is not a fix: the literal
    // wrapped across two lines in the README it was removed from
    const text = readFileSync(join(LANE, f), 'utf8').replace(/\s+/g, ' ');
    assert.ok(!/daemon is not reachable from this machine/i.test(text), `${f} still asserts the daemon's state`);
    assert.ok(!/the WSL distro has no docker CLI/i.test(text), `${f} still asserts what the distro has`);
    assert.ok(!/docker: NOT DONE/i.test(text), `${f} still carries the unconditional NOT DONE literal`);
  }
  // THE POSITIVE CONTROL. Three needles reporting zero prove nothing unless they
  // can be shown to fire, and this repository refuses a check that cannot: a
  // reworded literal would make all three silently clean. The control is the
  // text that was actually removed.
  const wasThere = ['docker: NOT DONE. The daemon is not reachable from this machine and the WSL',
    'distro has no docker CLI, so a container per upstream release was not'].join(' ');
  assert.ok(/daemon is not reachable from this machine/i.test(wasThere));
  assert.ok(/the WSL distro has no docker CLI/i.test(wasThere));
  assert.ok(/docker: NOT DONE/i.test(wasThere));
  // and it is STILL in data/version-ladder.txt, which is not a source file but a
  // record of a run from before the probe existed. It is not corrected by hand:
  // a record is what a run produced. See the note in README.md and the pin in
  // records.test.mjs; the next --write-data run replaces it with a measurement.
  const record = readFileSync(join(LANE, 'data/version-ladder.txt'), 'utf8').replace(/\s+/g, ' ');
  assert.ok(/daemon is not reachable from this machine/i.test(record),
    'data/version-ladder.txt was re-measured: drop this pin, the README note and the one in records.test.mjs');
});

// --------------------------------------------------------------- end to end --

test('requesting a docker rung is a NON-ZERO refusal naming a probe, and never a download', () => {
  // Runs the real runner. Which probe is named depends on the machine, and that
  // is the point: on a box with no CLI it is `docker --version`, on this one it
  // is `docker info`, and on a box with a daemon and no image it is
  // `docker image inspect` -- which is a refusal too, because the lane will not
  // fetch the image it was asked to measure.
  const dir = mkdtempSync(join(tmpdir(), 'vg-vl-docker-'));
  try {
    const pins = join(dir, 'pins.json');
    const digest = `sha256:${'a'.repeat(64)}`;
    writeFileSync(pins, JSON.stringify({ 'docker-gcc-13': digest }), 'utf8');
    const r = spawnSync(process.execPath, [RUNNER, '--out', join(dir, 'out'), '--ccs', 'docker-gcc-13',
      '--opts', '-O2', '--ids', 'haiku_E_aeskey_r1', '--no-subjects', '--docker-pins', pins],
    { encoding: 'utf8', timeout: 180000 });
    assert.equal(r.status, 5, `expected exit 5, got ${r.status}\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /docker rung not obtained/);
    assert.match(r.stderr, /docker (--version|info|image inspect)/);
    assert.match(r.stderr, /docker-gcc-13/);
    // no ladder was printed, and no measurement was claimed
    assert.doesNotMatch(r.stdout, /first appearance/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an unpinned docker rung is refused before anything touches a daemon', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-vl-docker-'));
  try {
    const r = spawnSync(process.execPath, [RUNNER, '--out', join(dir, 'out'), '--ccs', 'docker-gcc-13',
      '--opts', '-O2', '--ids', 'haiku_E_aeskey_r1', '--no-subjects'],
    { encoding: 'utf8', timeout: 180000 });
    assert.equal(r.status, 5, `expected exit 5, got ${r.status}\n${r.stderr}`);
    assert.match(r.stderr, /no digest is pinned/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a pins file naming a rung the ladder does not declare is a bad argument, not a measurement', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-vl-docker-'));
  try {
    const pins = join(dir, 'pins.json');
    writeFileSync(pins, JSON.stringify({ 'docker-gcc-99': `sha256:${'b'.repeat(64)}` }), 'utf8');
    const r = spawnSync(process.execPath, [RUNNER, '--out', join(dir, 'out'), '--ids', 'haiku_E_aeskey_r1',
      '--no-subjects', '--docker-pins', pins], { encoding: 'utf8', timeout: 180000 });
    assert.equal(r.status, 4, `expected exit 4, got ${r.status}\n${r.stderr}`);
    assert.match(r.stderr, /not a declared docker rung/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
