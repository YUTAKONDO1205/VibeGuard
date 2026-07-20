// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: node-net-import (node:https)
import { request } from 'node:https';

export function report(payload) {
  const req = request({ host: 'telemetry.example.invalid', method: 'POST', path: '/v1' });
  req.end(payload);
}
