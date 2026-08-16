/**
 * The CLI's door onto the shared lockfile reader (§17z-b).
 *
 * THE IMPLEMENTATION IS NO LONGER HERE. It moved to
 * `packages/analyzer-core/src/declared-packages.ts`, reachable as
 * `@vibeguard/analyzer-core/node`, and that file's header carries the whole
 * argument — why a lockfile and never a manifest, why exactly one directory is
 * searched, and why every failure path returns fewer names rather than more.
 * Read it there; nothing about the behaviour changed in the move.
 *
 * WHY IT MOVED, in one line: the VS Code extension needs the same names, and a
 * channel cannot share an implementation that lives inside another channel. It
 * did not share this one, so it shipped no veto at all — the same project
 * reported hallucinated-dependency findings in the editor that the command line
 * had already refuted with the lockfile sitting next to it. Two channels
 * disagreeing about one project is the parity violation this file's old
 * placement caused.
 *
 * WHY THIS FILE STILL EXISTS: `apps/cli/src/index.ts` imports
 * `./declared-packages.js`, and a re-export keeps that import — and any other
 * CLI-side reference — pointing at one name while the implementation lives
 * where both channels can reach it. It is a forwarding address, not a layer:
 * add nothing to it.
 */

export {
  readDeclaredPackages,
  lockfileStamp,
  type DeclaredPackagesResult,
} from '@vibeguard/analyzer-core/node';
