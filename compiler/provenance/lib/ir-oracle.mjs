// The oracle. interfaces.md §4.
//
//   Never decide whether an effect is present by searching for a symbol name.
//
// A deleted `memset` leaves `declare void @llvm.memset.p0.i64(...)` in the
// module. A grep for `llvm.memset` therefore keeps reporting the effect as
// present until some later pass sweeps unused declarations away — and then
// blames the sweeper for the loss. Measured on the prototype, the naive oracle
// and the call-site oracle named different passes and disagreed by nine
// pass-budget steps.
//
// So: count CALL SITES, and count them WITHIN ONE IR UNIT. The declaration is
// counted too, separately, so that a reader can see it is still there and that
// it was not what was counted.
//
// This lives in a library rather than inside the runner because a counting rule
// that is only exercised through a build is a counting rule nobody tests. The
// vectors in `test/ir-oracle.test.mjs` include the exact shape that defeats the
// naive version.

/**
 * @param {string} ll the text of a `.ll` file
 * @returns {{declares: number, perFunction: Record<string, number>, total: number}}
 *   `perFunction` is keyed by IR function name and counts memset call sites in
 *   that function only. `total` is their sum and excludes declarations.
 */
export function countMemsetCallSites(ll) {
  const perFunction = {};
  let current = null;
  let declares = 0;

  for (const raw of String(ll).split('\n')) {
    const line = raw.trim();

    // `declare` first: a declaration line mentions the intrinsic but is not a
    // call, and getting this order wrong is the whole bug being avoided.
    if (/^declare\b.*@llvm\.memset\b/.test(line)) { declares += 1; continue; }

    const def = /^define\b.*?@"?([A-Za-z0-9_.$]+)"?\s*\(/.exec(line);
    if (def) { current = def[1]; perFunction[current] = perFunction[current] ?? 0; continue; }
    if (line === '}') { current = null; continue; }

    if (current === null) continue;
    if (/(^|\s)(tail\s+|musttail\s+|notail\s+)?call\b[^;]*@llvm\.memset\b/.test(line)) {
      perFunction[current] += 1;
    }
  }

  const total = Object.values(perFunction).reduce((a, b) => a + b, 0);
  return { declares, perFunction, total };
}
