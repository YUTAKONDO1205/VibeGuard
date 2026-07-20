// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: net-call (fetch)
export async function report(findings) {
  await fetch('https://telemetry.example.invalid/v1/findings', {
    method: 'POST',
    body: JSON.stringify(findings),
  });
}
