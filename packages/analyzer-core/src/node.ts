/**
 * Node-only entry for analyzer-core — `@vibeguard/analyzer-core/node`.
 *
 * WHAT BELONGS HERE: capabilities that need a filesystem (or any other Node
 * built-in) and that MORE THAN ONE Node channel has to share. Today that is one
 * thing: reading a project's lockfile for the declared-package veto (§17z-b),
 * which the CLI, the GitHub Action (via the CLI) and the VS Code extension all
 * need to answer identically.
 *
 * WHAT DOES NOT BELONG HERE: anything a browser could want. The rule is not
 * "avoid `node:`" — `./index.js` already pulls in `node:fs` through `scanPath`
 * — it is that this door is the one every Node-only capability goes through, so
 * a reader can tell from an import line alone whether a module is browser-safe.
 *
 * WHY A SUBPATH AND NOT `index.ts`: a subpath is only bundled when it is
 * imported. `@vibeguard/sarif-adapter` set the precedent in 0.3.0-β with
 * `./node` → `provenance-node.js` (which reaches `node:child_process`) inside a
 * package both extensions import. The same shape here lets the editor and the
 * CLI share ONE lockfile reader — the thing they were not doing, which is how
 * the two channels came to disagree about the same project — without putting a
 * filesystem anywhere near the Chrome bundle.
 *
 * NEVER re-export this module from `index.ts` or `browser.ts`. The subpath is
 * load-bearing precisely because it is separate; folding it into either entry
 * would make every consumer of those entries a consumer of this one and delete
 * the property this file exists to provide.
 *
 * Chrome does not import it and must not: the browser has no lockfile to read,
 * and fetching one over the network would break the zero-egress guarantee that
 * is the extension's whole posture. See `extensions/chrome/src/shared/
 * block-scan.ts` for that ruling and the test that pins it.
 */

export {
  readDeclaredPackages,
  lockfileStamp,
  type DeclaredPackagesResult,
} from './declared-packages.js';
