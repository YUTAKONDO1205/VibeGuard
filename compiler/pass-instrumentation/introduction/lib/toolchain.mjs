// Reaching the toolchain from wherever this is being run.
//
// The sources are checked out on Windows and the compiler lives in a Linux
// distribution alongside it, so a runner started from the checkout has to cross
// that boundary; started from the distribution it must not. Both are ordinary,
// and the difference is confined here so that nothing else has to know.
//
// Two rules that cost time when they are learned the hard way:
//
//   * Arguments are passed as an argv array, never as a command string. An
//     outer shell expands `$VAR` and `$(...)` even inside single quotes, which
//     turns a path with a dollar in it -- and every mangled lambda name has one
//     -- into something else. spawnSync with `shell: false` has no outer shell.
//
//   * A missing tool is a failure, not a skip. `requireTool` throws; the caller
//     decides whether an environment variable authorises a skip, and if it does
//     the skipped case is named in the run's own output.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

export const DEFAULT_DISTRO = process.env.VG_INTRO_WSL_DISTRO ?? 'Ubuntu-24.04';

export function isLinux() {
  return process.platform === 'linux';
}

/**
 * A Windows path as the Linux side sees it: `C:\a\b` -> `/mnt/c/a/b`.
 * Already-Linux paths are returned unchanged.
 */
export function toLinuxPath(p) {
  const abs = resolve(p);
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(abs);
  if (!m) return abs.replace(/\\/g, '/');
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`;
}

/**
 * Run a tool, crossing into the distribution when we are not already in it.
 *
 * `envVars` are set for the tool. Crossing the boundary they cannot simply be
 * put in `spawnSync`'s environment -- this process's environment does not reach
 * the distribution, and a variable set here would silently not be set there,
 * which is how a build and the run that reads it end up pointing at two
 * different directories and the run reports "no log was produced". They are
 * therefore passed through `env`, which needs no shell and so cannot expand
 * anything in a value.
 */
export function runTool(tool, args, {
  distro = DEFAULT_DISTRO, cwd, input, allowFail = false, envVars = null,
} = {}) {
  const prefix = envVars
    ? ['env', ...Object.entries(envVars).filter(([, v]) => v != null).map(([k, v]) => `${k}=${v}`)]
    : [];
  const [cmd, argv] = isLinux()
    ? [prefix.length ? 'env' : tool, prefix.length ? [...prefix.slice(1), tool, ...args] : args]
    : ['wsl.exe', ['-d', distro, '--', ...prefix, tool, ...args]];
  const r = spawnSync(cmd, argv, {
    cwd, input, encoding: 'utf8', shell: false, maxBuffer: 256 * 1024 * 1024,
  });
  if (r.error) {
    if (allowFail) return { status: 127, stdout: '', stderr: String(r.error.message) };
    throw new Error(`${tool}: ${r.error.message}`);
  }
  if (r.status !== 0 && !allowFail) {
    throw new Error(`${tool} exited ${r.status}\n${r.stderr ?? ''}`);
  }
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** Is the tool there? Returns its version banner, or null. */
export function probeTool(tool, versionArg = '--version', opts = {}) {
  const r = runTool(tool, [versionArg], { ...opts, allowFail: true });
  if (r.status !== 0) return null;
  return (r.stdout || r.stderr).split('\n')[0].trim();
}

/**
 * The tool must be here. Throwing is the point: a checker that turns a missing
 * compiler into a skip reports the same green as a checker that ran.
 */
export function requireTool(tool, versionArg = '--version', opts = {}) {
  const banner = probeTool(tool, versionArg, opts);
  if (banner === null) {
    throw new Error(
      `${tool} is not available${isLinux() ? '' : ` through wsl -d ${opts.distro ?? DEFAULT_DISTRO}`}. `
      + 'Introduction analysis needs it; refusing to report a result it did not measure.',
    );
  }
  return banner;
}

/**
 * Scratch on the Linux side. interfaces.md §1: builds and measurements never go
 * under compiler/, because a build directory reached over the mount is slow,
 * takes CRLF ambiguity into digests, and bakes machine-specific paths into
 * recorded output.
 *
 * The home directory is read with `printenv`, not with a shell expansion of
 * `$HOME`: there is no shell in the pipe from here to the tool, so a `$` in an
 * argument is a `$` and nothing expands it. Asking the distribution what its
 * home directory is, rather than writing one down, is also what keeps a
 * machine's account name out of this file.
 */
export function labDir(opts = {}) {
  if (process.env.INTRO_LAB_DIR) return process.env.INTRO_LAB_DIR;
  return `${distroHome(opts)}/vg-lab/pass-introduction`;
}

/** Where the plugin is built. Same rules, same reasons. */
export function buildDir(opts = {}) {
  if (process.env.INTRO_BUILD_DIR) return process.env.INTRO_BUILD_DIR;
  return `${distroHome(opts)}/vg-build/pass-introduction`;
}

function distroHome(opts = {}) {
  const r = runTool('printenv', ['HOME'], { ...opts, allowFail: true });
  const home = r.status === 0 ? r.stdout.trim() : '';
  if (!home) {
    throw new Error('cannot determine the home directory to build and measure under; '
      + 'set INTRO_BUILD_DIR and INTRO_LAB_DIR');
  }
  return home;
}
