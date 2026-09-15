/**
 * The docker rung: a rung of the ladder identified by an IMAGE and a DIGEST
 * rather than by a binary this machine's package manager put on the PATH.
 *
 * WHY THE LADDER NEEDS ONE. Every other rung of this lane comes from `apt` on
 * one Ubuntu release, and that makes the whole ladder a DISTRIBUTION ladder: it
 * can say `gcc-11` and it cannot say WHICH 11. The release carries exactly one
 * build of each series, so `gcc-11` here is 11.5.0 and no other point release is
 * reachable, and nothing on the ladder can separate "the elimination arrived in
 * gcc 11" from "the elimination arrived in the patch level this distribution
 * happened to ship". A docker rung is what extends the ladder past that edge:
 * an image pinned by digest is one specific upstream build, several of them can
 * exist for one major, and the same major can be compared across distributions.
 *
 * WHY IT IS A SEPARATE LADDER AND NOT MORE RUNGS ON THE GCC ONE. `gcc-13` from
 * apt and a digest-pinned image at 13 are not two readings of the same rung:
 * they are different builds, different libc headers and different
 * _FORTIFY_SOURCE defaults. Filing them under one ladder would let a
 * cross-DISTRIBUTION difference print as a cross-VERSION one, which is the
 * exact confusion this lane exists to prevent. So the docker rungs are declared
 * here, counted on a line of their own, and the question they answer is the one
 * in `crossDistro()`: at the OVERLAPPING major, does the image agree with apt?
 *
 * THE DIGESTS ARE NOT IN THIS FILE, AND THAT IS DELIBERATE. A digest is
 * evidence, not a declaration -- it is the same kind of fact as the sha256 of
 * the apt binary the runner records, and it can only be obtained from a
 * registry. Writing one here that nobody on this machine has ever resolved
 * would be a fabricated measurement in a tracked file. So the declared rung
 * carries repository and tag, and the digest arrives from the operator's pins
 * file (`--docker-pins`). A rung with no pinned digest is REFUSED: a tag is a
 * moving name and a moving name is not a rung, which is the identity guard's
 * whole argument applied one layer up.
 *
 * NOTHING HERE FETCHES. Every invocation this file composes carries
 * `--pull=never`, so a missing image is a named refusal and never an implicit
 * multi-gigabyte download, and `--network=none` so the compile cannot reach a
 * network either. `compiler/schema/interfaces.md` section 1 states the rule for
 * the whole directory -- nothing there opens a socket and nothing fetches a
 * build description -- and this file is where a lane that runs containers could
 * most easily have broken it.
 *
 * All pure. Nothing here spawns anything or reads a file; the runner does that
 * and hands the results back in. That is what makes the refusal testable on a
 * machine with no daemon, which is every machine this has run on so far.
 */
import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';

/** The name of the declared docker ladder, as rows and the report spell it. */
export const DOCKER_LADDER_NAME = 'docker-gcc';

/**
 * The declared docker ladder, lowest first.
 *
 * gcc only, and the omission is a decision rather than an oversight: the Docker
 * Official Images set carries a `gcc` image with a tag per release series, and
 * carries no clang image at all. A clang docker ladder would therefore be some
 * third party's packaging of clang, and a rung whose packaging nobody can
 * account for measures the packaging rather than the release -- the thing a
 * docker rung was added to see past. If an upstream-owned clang image appears
 * it is declared here, and nothing else in this file needs to change.
 *
 * `program` is the compiler binary INSIDE the image. It is named rather than
 * assumed because the identity probe runs it, and an image whose `gcc` is a
 * wrapper for another version is the containerised form of the symlink the
 * native identity guard exists for.
 */
export const DOCKER_LADDER = Object.freeze([10, 11, 12, 13, 14].map((major) => Object.freeze({
  cc: `docker-gcc-${major}`,
  ladder: DOCKER_LADDER_NAME,
  nativeVendor: 'gcc',
  nativeCc: `gcc-${major}`,
  major,
  repository: 'gcc',
  tag: String(major),
  program: 'gcc',
})));

/** The declared docker rungs, as `--ccs` spells them, lowest first. */
export function dockerRungs() {
  return DOCKER_LADDER.map((r) => r.cc);
}

/** Is this `--ccs` token a declared docker rung? */
export function isDockerRung(cc) {
  return DOCKER_LADDER.some((r) => r.cc === cc);
}

/** The declared rung record for a `--ccs` token, or null. */
export function dockerRung(cc) {
  return DOCKER_LADDER.find((r) => r.cc === cc) || null;
}

/**
 * The only digest form this lane accepts.
 *
 * A tag is refused everywhere a digest is asked for. A tag names whatever the
 * registry is serving under it today; a digest names one image and cannot come
 * to mean another. The whole output is indexed by rung, and a rung that is
 * secretly another rung does not fail anywhere -- it compiles, it produces a
 * verdict, and the verdict is filed under the wrong version.
 */
export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/** null when `digest` can identify a rung, otherwise the refusal in full. */
export function digestProblem(cc, digest) {
  if (digest === null || digest === undefined || digest === '') {
    return `${cc}: no digest is pinned for this rung. A docker rung is an IMAGE AND A DIGEST -- `
      + 'a tag is a moving name, and a rung that can come to mean another build would file its '
      + 'verdicts under the wrong version exactly the way a symlinked clang-17 would. '
      + 'Pin it with --docker-pins (README.md, "Making the docker rung runnable")';
  }
  if (typeof digest !== 'string' || !DIGEST_RE.test(digest)) {
    return `${cc}: ${JSON.stringify(digest)} is not a digest of the form sha256:<64 hex>`;
  }
  return null;
}

/** `repository@sha256:...` for a declared rung and a valid digest. Throws otherwise. */
export function imageRef(rung, digest) {
  if (!rung || !rung.repository) throw new TypeError('imageRef: not a declared docker rung');
  const bad = digestProblem(rung.cc, digest);
  if (bad) throw new TypeError(`imageRef: ${bad}`);
  return `${rung.repository}@${digest}`;
}

/**
 * null when a pins object can be used, otherwise the refusal.
 *
 * A pin for a rung that is not declared is refused rather than ignored: the
 * ladder is declared and not discovered, and a pins file that quietly
 * introduced a rung would be the discovery route back in.
 */
export function pinsProblem(pins) {
  if (pins === null || pins === undefined) return null;
  if (typeof pins !== 'object' || Array.isArray(pins)) {
    return 'the pins file must hold a JSON object mapping a declared docker rung to its sha256 digest';
  }
  for (const [cc, digest] of Object.entries(pins)) {
    if (!isDockerRung(cc)) {
      return `the pins file names ${cc}, which is not a declared docker rung (${dockerRungs().join(', ')}). `
        + 'The ladder is declared in lib/docker.mjs and a pins file may not add to it';
    }
    const bad = digestProblem(cc, digest);
    if (bad) return `the pins file is unusable: ${bad}`;
  }
  return null;
}

/**
 * null when every `--ccs` token may be used, otherwise the refusal.
 *
 * THE ASYMMETRY THIS CLOSES. `--docker-pins {"docker-gcc-15": ...}` was exit 4
 * -- a pins file may not introduce a rung -- while `--ccs docker-gcc-15` was
 * recorded as an apt compiler that is not installed, because `docker-gcc-15` is
 * not a declared docker rung and so fell through to the native path, where it
 * became a `not-installed` line in the counting and a PATH binary that can never
 * exist. One spelling of the same mistake refused by name and the other filed as
 * a measurement is worse than either: the refusal teaches the reader that the
 * ladder is declared, and the silent line teaches them that rung 15 was tried.
 */
export function undeclaredDockerCcProblem(ccs) {
  for (const cc of ccs || []) {
    if (typeof cc !== 'string' || !/^docker-/.test(cc) || isDockerRung(cc)) continue;
    return `--ccs names ${cc}, which is not a declared docker rung (${dockerRungs().join(', ')}). `
      + 'The ladder is declared in lib/docker.mjs and --ccs may not add to it, exactly as a pins file '
      + 'may not. A token spelled like a docker rung is never tried as a compiler on the PATH';
  }
  return null;
}

// ------------------------------------------------------ THE NEVER-FETCH GATE --

/**
 * The docker subcommands this lane is allowed to run, and what each one must
 * carry. Every other subcommand is refused BY DEFAULT, which is the half a text
 * scan cannot do: a scan looks for the spellings somebody thought of, and this
 * table refuses the ones nobody did.
 *
 * `implicitlyPulls` is the reason the table exists. `docker run` and
 * `docker create` fetch a missing image unless told not to -- the flag's own
 * default is `missing`, i.e. fetch -- so for those two the gate REQUIRES
 * `--pull=never` rather than hoping the composer remembered it. That is the
 * exact hole in the previous contract: a second composer added later with a
 * plausible default would have passed the source scan and pulled a gigabyte.
 */
const ALLOWED_DOCKER_COMMANDS = Object.freeze({
  '--version': { sub: null, implicitlyPulls: false },
  version: { sub: null, implicitlyPulls: false },
  info: { sub: null, implicitlyPulls: false },
  image: { sub: ['inspect'], implicitlyPulls: false },
  run: { sub: null, implicitlyPulls: true },
  create: { sub: null, implicitlyPulls: true },
});

/** Flags a fetching invocation is composed out of, wherever they appear. */
const FETCHING_FLAGS = Object.freeze(['--pull', '--pull-always', '-a', '--all-tags']);

/**
 * Why this argv may not be run, in full, or null when it may.
 *
 * THE CONTRACT IS STRUCTURAL HERE AND TEXTUAL ONLY AS A BACKSTOP. The lane's
 * rule -- nothing in `compiler/` fetches (interfaces.md section 1) -- used to be
 * enforced by a test that grepped this file for the string `--pull=never`. That
 * test cannot see a SECOND composer: `docker run` without the flag fetches by
 * default, so an argv built anywhere else, with any plausible default, would
 * have grepped clean and pulled. Now every docker argv the runner spawns is
 * passed through this function first, so the refusal is a property of the
 * invocation rather than of the source text that happened to be scanned.
 */
export function neverFetchProblem(argv) {
  if (!Array.isArray(argv) || !argv.length) {
    return 'a docker invocation must be a non-empty argv array';
  }
  const words = argv.map((x) => String(x));
  const head = words[0];
  const spec = Object.prototype.hasOwnProperty.call(ALLOWED_DOCKER_COMMANDS, head)
    ? ALLOWED_DOCKER_COMMANDS[head] : null;
  if (!spec) {
    return `docker ${head}: this lane runs only ${Object.keys(ALLOWED_DOCKER_COMMANDS).join(', ')}. `
      + 'Every other subcommand is refused by default, because a subcommand nobody listed is a '
      + 'subcommand nobody checked cannot fetch';
  }
  if (spec.sub && !spec.sub.includes(words[1])) {
    return `docker ${head} ${words[1] ?? '(nothing)'}: only ${spec.sub.map((s) => `${head} ${s}`).join(', ')} `
      + 'is allowed here -- `image pull` is a fetch and `image inspect` reads the local store';
  }
  // Only docker's OWN arguments are scanned. Everything from the image
  // reference on is the command run INSIDE the container, and a compiler
  // argument that happens to spell a docker word is not a docker word.
  const refAt = words.findIndex((w) => w.includes('@sha256:'));
  const end = refAt === -1 ? words.length : refAt;
  for (let i = 1; i < end; i++) {
    const w = words[i];
    if (w === '--') break;
    if (w === 'pull') {
      return `\`pull\` appears as argv[${i}]: this lane does not fetch. A missing image is a refusal `
        + 'naming what is missing (README.md, "Making the docker rung runnable")';
    }
    if (/^--pull(=|$)/.test(w)) {
      const value = w.includes('=') ? w.slice(w.indexOf('=') + 1) : words[i + 1];
      if (value !== 'never') {
        return `--pull=${value ?? '(unset)'}: the only value this lane may pass is never. `
          + "docker's own default is `missing`, which fetches";
      }
    } else if (FETCHING_FLAGS.includes(w) && w !== '--pull') {
      return `${w}: a flag that fetches has no place in this lane`;
    }
  }
  if (spec.implicitlyPulls) {
    // docker's own arguments only, for the same reason as the loop above.
    const dockerWords = words.slice(0, end);
    if (!dockerWords.includes('--pull=never')) {
      return `docker ${head} carries no --pull=never. THIS IS THE DEFAULT THAT FETCHES: without the flag `
        + 'docker pulls a missing image, so a rung named at a prompt becomes several gigabytes off a network';
    }
    if (!dockerWords.includes('--network=none')) {
      return `docker ${head} carries no --network=none: the compile may not reach a network either`;
    }
  }
  return null;
}

/** The same gate, as the throw every composer and every spawn goes through. */
export function assertNeverFetches(argv) {
  const why = neverFetchProblem(argv);
  if (why) throw new TypeError(`this lane never fetches: ${why}`);
  return argv;
}

// --------------------------------------------------------------- the probes --

/** `docker --version` -- is there a CLI at all? */
export function cliProbeArgv() {
  return assertNeverFetches(['--version']);
}

/** `docker info` -- is a DAEMON reachable? A CLI that answers --version is not one. */
export function daemonProbeArgv() {
  return assertNeverFetches(['info', '--format', '{{.ServerVersion}}']);
}

/**
 * `docker image inspect <ref>` -- is the image ALREADY in the local store?
 *
 * inspect is the probe rather than `pull` on purpose: inspect reads the local
 * image store and never reaches a registry, so an absent image ends as a
 * refusal naming what is missing and never as a download nobody asked for.
 */
export function imageInspectArgv(ref) {
  return assertNeverFetches(['image', 'inspect', '--format', '{{.Id}}', ref]);
}

/**
 * The compile invocation for a docker rung.
 *
 * `--pull=never` is the contract of this lane and the tests assert it rather
 * than trusting it: without the flag, `docker run` on a missing image PULLS,
 * which turns a refusal into several gigabytes off a network in a tree whose
 * stated rule is that nothing fetches. `--network=none` is the same rule
 * applied to the compile itself.
 *
 * Sources and outputs are BASENAMES inside the mounted directory. That is not
 * tidiness: the host path is mounted once and never appears in a compiler
 * argument, so nothing composed out of the compile line can carry one.
 */
export function dockerRunArgv({ ref, program, args, hostDir, guestDir = '/vg', user = null }) {
  if (typeof ref !== 'string' || !ref.includes('@sha256:')) {
    throw new TypeError(`dockerRunArgv: ${JSON.stringify(ref)} is not a digest-pinned image reference`);
  }
  if (typeof program !== 'string' || !program) throw new TypeError('dockerRunArgv: no program to run');
  if (typeof hostDir !== 'string' || !hostDir) throw new TypeError('dockerRunArgv: no host directory to mount');
  const argv = ['run', '--rm', '--pull=never', '--network=none'];
  if (user) argv.push('--user', String(user));
  argv.push('-v', `${hostDir}:${guestDir}`, '-w', guestDir, ref, program, ...(args || []));
  // The gate, not the comment above it, is what makes the flag mandatory: this
  // throws if a later edit drops --pull=never or --network=none from the line.
  return assertNeverFetches(argv);
}

/**
 * A probe detail that is safe to write into a tracked record.
 *
 * A daemon's error text is written by the daemon, and a daemon is entitled to
 * quote a socket path, a mount point or a home directory in it. The runner
 * refuses to write any text carrying one (exit 5), so an unredacted detail
 * would turn "docker is not running" into a failed run with a puzzling reason.
 * The marker NAMES are kept -- what is dropped is the text around them, which
 * is the part that must not be published.
 */
export function safeDetail(detail) {
  if (typeof detail !== 'string' || !detail) return '';
  const one = detail.replace(/\s+/g, ' ').trim().slice(0, 200);
  const hits = detailPathHits(one);
  if (hits.length) return `(detail withheld: it carries ${hits.join(', ')})`;
  return one;
}

/**
 * The markers a DAEMON's error text carries that the shared provenance scan
 * does not look for.
 *
 * The shared list (`repair-loop/lib/provenance.mjs`) is about a MEASUREMENT
 * carrying the measuring machine's layout: `/home/`, `/root/`, `/mnt/`,
 * `/Users/`, a drive letter. The canonical Linux refusal is
 *
 *   Cannot connect to the Docker daemon at unix:///var/run/docker.sock
 *
 * and it carries none of them -- `/var/run/` is not on the list and `unix://`
 * does not read as a drive letter -- so the most likely detail this lane will
 * ever redact was being published verbatim into a tracked manifest. The Windows
 * spelling (`npipe:////./pipe/dockerDesktopLinuxEngine`) has the same problem.
 *
 * These are added HERE rather than in the shared list because they are a fact
 * about docker's error prose and not about this repository's provenance rule,
 * and `repair-loop/` belongs to another lane. The marker NAMES are what is
 * reported; the text around them is what must not be.
 */
export const DAEMON_PATH_MARKERS = Object.freeze([
  'unix://', 'npipe://', 'tcp://', 'fd://', 'ssh://', '/var/run/', '/run/', '/tmp/', '/proc/', '.sock', '\\pipe\\', '/pipe/',
]);

/** Every path-ish marker in a docker detail: the shared list plus the daemon's own. */
export function detailPathHits(text) {
  if (typeof text !== 'string') return [];
  const hits = [...absolutePathHits(text)];
  for (const m of DAEMON_PATH_MARKERS) if (text.includes(m) && !hits.includes(m)) hits.push(m);
  return hits;
}

/**
 * What the docker side of this machine is, from what the probes returned.
 *
 * `probes.cli` and `probes.daemon` are `{ok, detail}`, or null for "not
 * attempted". The returned object is the ONLY thing the report's docker
 * sentence is built from: it says unreachable because a NAMED probe failed, and
 * the moment that probe starts answering the sentence changes by itself. The
 * literal it replaces said the daemon was unreachable whether or not it was.
 */
export function dockerStatus(probes = {}) {
  const cli = probes.cli ?? null;
  const daemon = probes.daemon ?? null;
  if (!cli) {
    // NOT PROBED is its own state and never a failed probe. The runner only
    // spends the two subprocesses when a docker rung was asked for, so the
    // common case is that nothing was attempted -- and a report that said
    // "`docker --version` failed on this machine" about a command nobody ran
    // would be the same fabrication as the literal this whole file replaced.
    return {
      probed: false,
      reachable: false, failedProbe: null, reason: 'no docker rung was requested, so nothing was probed',
      cliVersion: null, serverVersion: null,
    };
  }
  if (!cli.ok) {
    return {
      probed: true,
      reachable: false,
      failedProbe: 'docker --version',
      reason: `no docker CLI answered: ${safeDetail(cli.detail) || 'the command could not be run'}`,
      cliVersion: null,
      serverVersion: null,
    };
  }
  if (!daemon) {
    return {
      probed: true,
      reachable: false, failedProbe: 'docker info', reason: 'the daemon was never probed',
      cliVersion: safeDetail(cli.detail), serverVersion: null,
    };
  }
  if (!daemon.ok) {
    return {
      probed: true,
      reachable: false,
      failedProbe: 'docker info',
      reason: `a docker CLI answered but no daemon did: ${safeDetail(daemon.detail) || 'the command failed'}`,
      cliVersion: safeDetail(cli.detail),
      serverVersion: null,
    };
  }
  return {
    probed: true,
    reachable: true, failedProbe: null, reason: null,
    cliVersion: safeDetail(cli.detail), serverVersion: safeDetail(daemon.detail),
  };
}

/**
 * Why this docker rung cannot be obtained, in full, or null when it can.
 *
 * The order is the order the probes have to pass in, and each refusal names the
 * command that failed rather than asserting a state: "the daemon is not
 * reachable" is a claim, `docker info` returning non-zero is a reading.
 */
export function rungProblem({ cc, digest, status, image = null }) {
  if (!isDockerRung(cc)) return `${cc} is not a declared docker rung (${dockerRungs().join(', ')})`;
  const badDigest = digestProblem(cc, digest);
  if (badDigest) return badDigest;
  const ref = imageRef(dockerRung(cc), digest);
  if (!status || !status.reachable) {
    const probe = (status && status.failedProbe) || '(no probe was run)';
    return `${cc} (${ref}): the probe \`${probe}\` did not establish a usable docker: `
      + `${(status && status.reason) || 'no probe was run'}. The rung is declared and it was not obtained; `
      + 'nothing here reports it as measured';
  }
  if (!image) {
    return `${cc} (${ref}): the image was never probed, so nothing was established about it`;
  }
  if (!image.ok) {
    return `${cc}: \`docker image inspect ${ref}\` found no such image in the local store: `
      + `${safeDetail(image.detail) || 'inspect failed'}. This lane runs with --pull=never, so a missing `
      + 'image is a refusal and never a download: pull it yourself first (README.md, '
      + '"Making the docker rung runnable") and run again';
  }
  return null;
}

/**
 * The counting line for the docker half of the ladder.
 *
 * Separate from versionCounting() because the two ladders answer different
 * questions, and pooling the denominators would let five rungs that have never
 * produced a cell dilute the eleven that have. Every declared rung is here,
 * obtained or not, and a rung that is neither obtained nor carries a reason
 * breaks the accounting rather than passing quietly -- the rule the native
 * counting line is already held to.
 */
export function dockerCounting(versions) {
  const declared = DOCKER_LADDER.length;
  const mine = (versions || []).filter((v) => v && isDockerRung(v.cc));
  const obtained = mine.filter((v) => v.obtained).length;
  const skipped = mine.filter((v) => !v.obtained).length;
  const withReason = mine.filter((v) => !v.obtained && typeof v.reason === 'string' && v.reason).length;
  return {
    declared,
    obtained,
    skipped,
    accountedFor: obtained + skipped === declared && withReason === skipped,
  };
}

/**
 * Does the docker rung agree with the apt rung at the overlapping major?
 *
 * This is what a docker rung is FOR in this lane, and it is the only question
 * the docker ladder can answer on its own terms: the tracked find-step rows are
 * apt rows, so no docker rung is an anchor rung, and a run made only of docker
 * rungs is unanchored and exits 2 like any other. What a docker rung CAN be
 * joined to is the apt rung of the same major in the same run -- the image at
 * 13 against `gcc-13` on the same (id, opt) -- and a disagreement there is a
 * cross-DISTRIBUTION finding rather than a fault: two builds of one release
 * series differing on whether the wipe survives is a result, and a more
 * interesting one than the agreement.
 *
 * `problem` is non-null when docker rows exist and NOTHING was compared. 0 of 0
 * agreeing is not a pass here either: it is a run that obtained a docker rung
 * and no apt rung to read it against, and reporting that as agreement is the
 * defect this lane's anchor already refuses one layer up.
 */
/**
 * The exit code a cross-distribution problem takes.
 *
 * 3, and it is 3 for two reasons that agree. `interfaces.md` section 7 defines 3
 * as "a check could not be completed -- NEVER conflated with 0, this is the code
 * that keeps `we did not look` from being reported as `it is clean`", which is
 * exactly what a docker cell read against nothing is. And it is kept apart from
 * the anchor's 2 on purpose: 2 says nothing in the run is anchored and none of
 * it may be read, while this says the apt ladder above stands and the DOCKER
 * half established nothing. Folding them together would make a reader throw away
 * a good apt ladder over a container that had nothing to be read against.
 *
 * A code of its own (8, say) would have read better in this lane and would have
 * been a code `interfaces.md` section 7 does not define -- and this lane may not
 * add a row to that table. `compiler/schema/exit-codes.test.mjs` is the fence
 * that would have caught it; `test/wiring.test.mjs` asserts that whatever this
 * number is, section 7 defines it.
 */
export const CROSS_EXIT = 3;

export function crossDistro(rows) {
  const all = Array.isArray(rows) ? rows : [];
  // A row is a docker row if EITHER its `ladder` field says so or its rung name
  // is a declared docker rung, and the two disagreeing is a refusal rather than
  // a quiet reading. That is not belt-and-braces: `ladder` is the only thing
  // this join filters on, so dropping the field at the row constructor would
  // have made every docker row invisible here -- 0 docker rows, nothing to
  // compare, no problem reported, exit 0. The field is now load-bearing in a way
  // that FAILS when it goes missing.
  const isDocker = (r) => r.ladder === DOCKER_LADDER_NAME || isDockerRung(r.cc);
  const dockerRows = all.filter((r) => r && isDocker(r));
  const mislabelled = all.filter((r) => r && isDocker(r) && r.ladder !== DOCKER_LADDER_NAME)
    .map((r) => `${r.cc} (ladder=${JSON.stringify(r.ladder ?? null)})`);
  const nativeAt = new Map();
  for (const r of all) {
    if (!r || isDocker(r)) continue;
    if (r.vendor !== 'gcc') continue;
    nativeAt.set(`${r.id}|${r.major}|${r.opt}`, r.verdict);
  }
  const differences = [];
  let compared = 0;
  for (const r of dockerRows) {
    const key = `${r.id}|${r.major}|${r.opt}`;
    if (!nativeAt.has(key)) continue;
    compared++;
    const apt = nativeAt.get(key);
    if (apt !== r.verdict) {
      differences.push({ id: r.id, major: r.major, opt: r.opt, docker: r.verdict, apt });
    }
  }
  const vacuous = dockerRows.length && compared === 0
    ? `${dockerRows.length} docker cell(s) were measured and NONE could be compared with an apt rung at the `
      + 'same major, so "0/0 agree" would pass vacuously. A docker rung read against nothing says only that '
      + 'a container compiled: add the apt rung of the same major to --ccs'
    : null;
  const mislabel = mislabelled.length
    ? `${mislabelled.length} row(s) name a declared docker rung and are not filed on the ${DOCKER_LADDER_NAME} `
      + `ladder: ${mislabelled.join(', ')}. The row's \`ladder\` field is what this join and the report's `
      + 'off-ladder line read; a row whose two names disagree would be counted as an apt cell and compared '
      + 'with itself'
    : null;
  const problem = mislabel ?? vacuous;
  return {
    dockerRows: dockerRows.length, compared, agreed: compared - differences.length, differences, problem, mislabelled,
  };
}

/**
 * The report's docker paragraph, derived from the probe rather than asserted.
 *
 * The lines these replace were a literal in the report writer, printed on every
 * run whether or not they were true and copied from there into a tracked
 * record. That is a defect shape this repository has recorded before: prose
 * stating a state where a measurement belongs. These lines cannot say the
 * daemon is unreachable unless a named probe said so, and they stop saying it
 * the moment it answers.
 */
export function dockerReportLines({ status, requested = [], obtained = [], cross = null }) {
  const L = [];
  if (!status || !status.probed) {
    // NOT PROBED, and it says so. The probe costs two subprocesses and one of
    // them opens the daemon socket, so it is spent only when a docker rung was
    // asked for. Saying `docker info` failed here would be an assertion about a
    // command nobody ran -- the exact shape this file exists to remove.
    L.push(`  - the docker ladder (${DOCKER_LADDER.length} declared rungs: ${dockerRungs().join(', ')}) produced no cell.`);
    L.push('    NOT PROBED: this run asked for no docker rung, so nothing was run against a daemon and this');
    L.push('    report says nothing about whether one is reachable. Ask for a rung (--ccs docker-gcc-13');
    L.push('    --docker-pins <file>) and the probes run and are reported here.');
    L.push('    It is a limit on which BUILDS were reached, not a finding about any wipe: the apt');
    L.push('    ladder above is a DISTRIBUTION ladder and cannot speak about upstream point releases.');
    return L;
  }
  if (!status.reachable) {
    const why = (status && status.reason) || 'no probe was run';
    const probe = (status && status.failedProbe) || '(none run)';
    L.push(`  - the docker ladder (${DOCKER_LADDER.length} declared rungs: ${dockerRungs().join(', ')}) produced no cell.`);
    L.push(`    MEASURED, not assumed: the probe \`${probe}\` failed on this machine -- ${why}.`);
    L.push('    That is a reading about this machine on this run and it becomes false the moment the probe');
    L.push('    answers. It is a limit on which BUILDS were reached, not a finding about any wipe: the apt');
    L.push('    ladder above is a DISTRIBUTION ladder and cannot speak about upstream point releases.');
    return L;
  }
  L.push(`  - docker IS reachable on this machine (server ${status.serverVersion || 'version unreported'}).`);
  if (!requested.length) {
    L.push('    No docker rung was requested by this run, so none was obtained. The declared rungs are');
    L.push(`    ${dockerRungs().join(', ')}; add one to --ccs with its digest in --docker-pins.`);
    return L;
  }
  L.push(`    ${obtained.length} of ${requested.length} requested docker rung(s) were obtained.`);
  if (cross && cross.problem) {
    L.push(`    NOT COMPARED: ${cross.problem}.`);
    // The sentence and the exit code come from the same `problem`, so the
    // report cannot print this while the run exits 0 -- which is what it did
    // when NOT COMPARED was printed and nothing read it.
    L.push(`    Nothing was established about any wipe by the docker half of this run: it exits ${CROSS_EXIT}.`);
  } else if (cross && cross.compared) {
    L.push(`    cross-distribution: ${cross.agreed}/${cross.compared} cell(s) agree with the apt rung at the same major.`);
    for (const d of cross.differences) {
      L.push(`      ${d.id} ${d.opt} major ${d.major}: docker ${d.docker}, apt ${d.apt}`);
    }
  }
  return L;
}
