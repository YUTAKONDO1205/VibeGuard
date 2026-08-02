// VG-SMELL-041 NEGATIVE — the sanitizer is applied INLINE, inside the sink's
// own argument list, in a template interpolation.
//
// The `forLog` line is the one that makes this a real test rather than an
// obviously-safe file: it is a transformer applied to the same value whose
// result the response does NOT use, which is the shape the rule reports as
// BYPASSED. What keeps this file silent is that the sanitizer the response DOES
// use sits inside the sink's own arguments. Remove that condition from the rule
// and this directory starts firing.
//
// ★ AND IT IS VISIBLE, WHICH IS NOT WHAT THE DESIGN EXPECTED. The header of
// `taint/index.ts` says the indexer's blanker erases template interiors
// wholesale, which would hide `${escapeHtml(nickname)}` from the rule
// altogether. Dumping `StructureIndex.blanked` for this file shows otherwise —
// the literal text is blanked and the interpolated EXPRESSION survives — and the
// original-text fallback written for the belief was deleted as dead code. The
// measurement is recorded on the rule's own sanitised-at-the-sink check.
import { escapeHtml } from './security/html';

export function renderProfile(req: any, res: any) {
  const nickname = req.query.nick;
  const forLog = escapeHtml(nickname);
  console.log('rendering profile for %s', forLog);
  res.send(`<h1>${escapeHtml(nickname)}</h1>`);
}
