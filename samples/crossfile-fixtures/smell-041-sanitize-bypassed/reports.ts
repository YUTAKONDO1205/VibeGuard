// VG-SMELL-041 POSITIVE — the BYPASSED ordering, with a transforming sanitizer.
//
// Here the order on the page is right: the sanitizer runs before the file is
// opened. What is wrong is the DATA order — `sanitizeFilename` produced a safe
// copy and the copy is not the value that reached `fs.createReadStream`. The
// raw request value did, one line later, past a sanitizer that had already run.
//
// This is the shape that makes the rule taint-based rather than text-based: a
// reading of statement order alone (design手順書 §9.3, "`validate` の後に `save`
// がある") calls this file correct, because the sanitizer IS first.
import fs from 'node:fs';
import path from 'node:path';
import { sanitizeFilename } from './security/filename';

const REPORT_DIR = '/var/lib/reports';

export function downloadReport(req: any, res: any) {
  const requested = req.query.file;
  // The safe copy is computed…
  const safeName = sanitizeFilename(requested);
  // …and then the RAW name is the one that reaches the file system.
  const stream = fs.createReadStream(path.join(REPORT_DIR, requested));
  res.setHeader('X-Report-Name', safeName);
  stream.pipe(res);
}
