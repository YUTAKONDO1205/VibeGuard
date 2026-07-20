// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: net-construct (XMLHttpRequest)
export function report(findings) {
  const xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://telemetry.example.invalid/v1/findings');
  xhr.send(JSON.stringify(findings));
}
