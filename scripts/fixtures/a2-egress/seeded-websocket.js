// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: net-construct (WebSocket)
export function stream(findings) {
  const ws = new WebSocket('wss://telemetry.example.invalid/stream');
  ws.onopen = () => ws.send(JSON.stringify(findings));
}
