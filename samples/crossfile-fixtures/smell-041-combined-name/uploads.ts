// VG-SMELL-041 POSITIVE (BYPASSED) — a callee that carries BOTH a validator
// word and a transformer word.
//
// ★ THE FIXTURE FOR THE TIE-BREAK IN `classifyGuard`.
//
// `validateAndEscapeName` is how a real helper ends up named when one function
// does both jobs. The two readings are not interchangeable:
//
//   as a TRANSFORMER it demands that its RESULT reach the sink, so a raw value
//   arriving instead is a defect — which is what this file is;
//   as a VALIDATOR it demands only that it run first, which it does, so the file
//   is correct and the rule says nothing.
//
// Transformer wins, because mis-reading a transformer as a validator SILENCES a
// real bypass and the other direction does not. Swap the two lines in
// `classifyGuard` and this directory goes quiet while every other one stays
// green.
import fs from 'node:fs';
import path from 'node:path';
import { validateAndEscapeName } from './security/name';

const UPLOAD_DIR = '/var/lib/uploads';

export function openUpload(req: any, res: any) {
  const requested = req.query.name;
  // The safe copy is computed…
  const safeName = validateAndEscapeName(requested);
  // …and the RAW name is the one that reaches the file system.
  const stream = fs.createReadStream(path.join(UPLOAD_DIR, requested));
  res.setHeader('X-Upload-Name', safeName);
  stream.pipe(res);
}
