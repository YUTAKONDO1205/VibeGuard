#!/usr/bin/env python3
"""Read one linked executable for a subject wipe and its control, as JSON.

Imports `objdump_fill` from ../../../gcc-repair/scripts/ rather than copying it,
the way ../../../llvm-repair/scripts/check-fixture-loop.py does. There is one
disassembly oracle in this tree and this lane is not going to be the second.

  python3 read-wipe.py <exe> <caller> <helper|-> <bytes> <controlFn> <controlBytes>

Prints one JSON object: {"subject": <reading>, "control": <reading>,
"objdump": "<version line>"}. A reading is objdump_fill's own dict, including
its NOT_OBSERVED case -- which is passed through, not turned into an absence.
Exits 3 when the executable cannot be disassembled at all.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "gcc-repair", "scripts"))

import objdump_fill  # noqa: E402


def main(argv):
    if len(argv) != 7:
        print(__doc__, file=sys.stderr)
        return 4
    exe, caller, helper, nbytes, control_fn, control_bytes = argv[1:]
    helper = None if helper == "-" else helper
    objdump = os.environ.get("LTOW_OBJDUMP", "objdump")
    try:
        text = objdump_fill.disassemble(exe, objdump=objdump)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 3
    out = {
        "subject": objdump_fill.wipe_reading(text, caller, helper, int(nbytes)),
        "control": objdump_fill.wipe_reading(text, control_fn, None, int(control_bytes)),
        "objdump": objdump_fill.objdump_version(objdump=objdump),
    }
    out["subjectDescribed"] = objdump_fill.describe(out["subject"])
    out["controlDescribed"] = objdump_fill.describe(out["control"])
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
