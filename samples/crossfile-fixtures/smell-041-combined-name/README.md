# smell-041-combined-name — VG-SMELL-041 POSITIVE (BYPASSED)

A callee carrying **both** vocabularies: `validateAndEscapeName`.

Expected: exactly one `VG-SMELL-041`, `severity: medium` (a `file` sink),
`confidence: medium` (BYPASSED), primary location `uploads.ts:29`.

Falsifies the tie-break in `classifyGuard`. Read as a **transformer**, the helper
demands that its RESULT reach the sink and the raw value arriving instead is the
defect this file contains. Read as a **validator**, it demands only that it run
first — which it does — and the file is correct. Swapping the two lines in
`classifyGuard` turns this directory silent and leaves every other one green.

Transformer wins because the two errors are not symmetric: mis-reading a
transformer as a validator silences a real bypass, and mis-reading a validator as
a transformer at worst asks for a result nobody uses.
