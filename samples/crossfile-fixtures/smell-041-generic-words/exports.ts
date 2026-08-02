// VG-SMELL-041 NEGATIVE — three calls that carry a vocabulary word and are not
// security operations.
//
// ★ THE VOCABULARY FIXTURE, WRITTEN AFTER MEASUREMENT REMOVED THREE WORDS.
//
// `ensure`, `strip` and `quote` were in the rule's word sets, and each names
// what a function does to a value rather than why:
//
//   ensureParentDirectory   creates a directory. `ensure` is the ordinary word
//                           for "make this exist".
//   stripTrailingWhitespace text tidying. `strip` says nothing about a threat
//                           model.
//   quoteForDisplay         formatting. The corpus original was `quotePs`, a
//                           PowerShell argument quoter, and it cost the rule two
//                           of its three findings on 1,000 real repositories.
//
// All three calls sit AFTER the sink on purpose. Placed before it, a validator
// word would SUPPRESS the finding and the file would be silent whichever
// vocabulary was in force — proving nothing. Placed after it, each one is an
// INVERTED finding for as long as the word is admitted, so restoring any of the
// three to `TRANSFORMER_WORDS` or `VALIDATOR_WORDS` turns this directory red.
import fs from 'node:fs';
import path from 'node:path';
import { ensureParentDirectory } from './fsutil';
import { escapeRegExp, quoteForDisplay, stripTrailingWhitespace } from './text';

const EXPORT_DIR = '/var/lib/exports';

export function writeExport(req: any, res: any) {
  const target = req.query.target;
  fs.writeFileSync(path.join(EXPORT_DIR, target), 'exported\n');
  ensureParentDirectory(path.dirname(target));
  // `escapeRegExp` carries a word the vocabulary DOES admit, and is excluded by
  // name in `NOT_A_GUARD`: escaping a value for a pattern is not escaping it for
  // anything that matters here. Stop excluding it and this line alone reports.
  //
  // ★ WRITTEN AS TWO STATEMENTS ON PURPOSE. As `new RegExp(escapeRegExp(target))`
  // this line pins nothing: `CALL_RE` consumes the `(` of the OUTER call, so the
  // inner callee has no boundary character left to match against and the guard
  // is never collected. That is a measured limit of the rule, recorded in its
  // KNOWN GAPS — and a fixture standing on it would be silent for a reason that
  // has nothing to do with `NOT_A_GUARD`.
  const pattern = escapeRegExp(target);
  const label = stripTrailingWhitespace(target);
  res.send(quoteForDisplay(label) + String(new RegExp(pattern).source.length));
}
