// VG-SMELL-041 NEGATIVE — the sanitizer is applied inline at an ASSIGN-form
// sink.
//
// ★ THE FIXTURE FOR THE OTHER HALF OF `sinkArgumentSpan`.
//
// `el.innerHTML = value` is the one sink in H1's table that consumes its value
// through an `=` rather than through `(…)`. A span function that looks only for
// an opening parenthesis finds the SANITIZER's own parenthesis — the first one
// on the line — and concludes that `escapeHtml` sits outside the sink it is
// protecting, i.e. that it runs after it. The finding that follows accuses
// correctly written code.
//
// The `forLog` line is what makes the accusation reachable: it is a visible
// transformer applied to the same value whose result the sink does not use, so
// without the assign-form span this file has a qualifying guard, no on-path
// evidence, and reports BYPASSED. `smell-041-inline-at-sink/` cannot pin this,
// because its sink is a call and takes the other branch.
import { escapeHtml } from './security/html';

export function renderBanner(req: any, el: any) {
  const message = req.query.msg;
  const forLog = escapeHtml(message);
  console.log('rendering banner: %s', forLog);
  el.innerHTML = escapeHtml(message);
}
