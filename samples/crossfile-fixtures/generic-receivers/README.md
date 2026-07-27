# generic-receivers — VG-SMELL-010 POSITIVE (regression for a false negative)

Three inline `role !== 'admin'` checks across two controller files. The only
unusual thing about them is the receiver names: `entry`, `item`, `h` — ordinary
loop and local variable names.

An earlier version of the chat-message exclusion tested the receiver name
BEFORE looking at what was being compared against, so these were discarded as
"chat message roles" despite comparing against `'admin'`. Every one of them is a
textbook privilege check.

The receiver name is now only allowed to decide when no literal is available.

Expected: exactly one `VG-SMELL-010` finding.
