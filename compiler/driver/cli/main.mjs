// Shared entry point for vgcc and vg++.
//
// The one thing that happens here and nowhere else: lib/run.mjs statically
// imports the plugin integrity component, so if that component is absent the
// import fails at module resolution, before any of the driver's code runs. That
// failure is caught here and turned into exit 3.
//
// It is worth being explicit about why it is caught here rather than inside
// run.mjs. A try/catch around the import *in* run.mjs would need the import to
// be dynamic, and a dynamic import is a lookup — something that can quietly
// resolve to nothing and leave a `checkPlugins` that returns "fine". Keeping
// the import static means the only two outcomes are "the real check ran" and
// "the driver refused to start", and this file makes the second one exit 3
// instead of an unhandled rejection with exit 1, so a caller cannot mistake it
// for a compile error.

import { EXIT_INCOMPLETE } from '../lib/exit.mjs';

const PEER_MODULES = new Map([
  ['plugin-integrity/integrity.mjs', 'compiler/driver/plugin-integrity/integrity.mjs (exports checkPlugins)'],
]);

export async function main({ driverName, mode, argv = process.argv.slice(2) }) {
  let run;
  try {
    ({ run } = await import('../lib/run.mjs'));
  } catch (err) {
    if (err?.code === 'ERR_MODULE_NOT_FOUND') {
      const missing = [...PEER_MODULES.entries()].find(([k]) => String(err.message).includes(k));
      process.stderr.write(
        `${driverName}: cannot start — ${missing ? missing[1] : 'a required module'} is not present.\n`
        + `${driverName}: exit ${EXIT_INCOMPLETE} (a check could not be completed). `
        + 'The build was not run, because a build this driver did not check is not a build it can report as clean.\n'
        + `${driverName}: ${err.message}\n`,
      );
      return EXIT_INCOMPLETE;
    }
    throw err;
  }

  return run({
    argv,
    cwd: process.cwd(),
    driverName,
    mode,
    env: process.env,
    stdout: process.stdout,
    stderr: process.stderr,
  });
}

export async function cli(opts) {
  try {
    process.exitCode = await main(opts);
  } catch (err) {
    process.stderr.write(`${opts.driverName}: internal error: ${err?.stack ?? err}\n`);
    // An internal error is a check that did not complete. Not 0, and not 1 —
    // 1 means the compiler failed, and saying that here would send whoever
    // reads it to look at their source code.
    process.exitCode = EXIT_INCOMPLETE;
  }
}
