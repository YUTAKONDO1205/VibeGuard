// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: net-call (fetch), reached through an aliased global and a
// computed member access — the shapes a bundler or a minifier produces, and the
// shapes a naive `grep "fetch("` misses because the text `fetch(` never occurs.
const g = globalThis;

export async function report(findings) {
  await g['fetch']('https://telemetry.example.invalid/v1', { method: 'POST', body: findings });
}
