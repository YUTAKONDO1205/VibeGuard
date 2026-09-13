#!/usr/bin/env python3
"""Every document in the results directory is one the catalogue accounts for.

check-meta.py with no arguments grades every `*.json` in `$VG_META_OUT` and
reports a verdict over "all N document(s)". N is whatever is in the directory --
so a leftover from a run id since removed from the catalogue, or a document
another lab pointed at the same directory left behind, is graded as part of this
sweep and counted in that sentence. The grade is then over a set the lane's own
table does not describe, and nothing says so.

The opposite direction matters just as much and is checked here too: a
configuration the catalogue declares whose document is absent means the sweep is
half a sweep. check-meta.py cannot catch that one at all -- it can only see what
is in the directory, and a missing document is not in it.

Refused, never deleted: this script does not own that directory, and a harness
that tidies away a measurement it did not recognise is a harness that can destroy
the one run that mattered.

Exit codes (interfaces.md section 7):
  0  one document per declared configuration, and nothing else
  3  a document no configuration accounts for, a declared configuration with no
     document, or no results directory at all -- a check that could not be
     completed, never conflated with 0
"""

import json
import os
import sys


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: account-for-documents.py <results-dir> <catalogue.json>\n")
        return 3
    reports, catalogue = argv

    try:
        with open(catalogue, encoding="utf-8") as fh:
            declared = [c["runId"] for c in json.load(fh)["configurations"]]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        sys.stderr.write("could not read the configurations out of %s: %s\n"
                         % (catalogue, exc))
        return 3

    if not os.path.isdir(reports):
        sys.stderr.write("no report directory at %s; nothing was assembled\n" % reports)
        return 3

    found = sorted(n for n in os.listdir(reports) if n.endswith(".json"))
    declared_set = set(declared)
    stray = [n for n in found if os.path.splitext(n)[0] not in declared_set]
    missing = [r for r in declared if r + ".json" not in found]

    for n in stray:
        sys.stderr.write(
            "%s: no configuration in catalogue.json accounts for this document, and "
            "check-meta.py would grade it as part of this sweep and count it in its "
            "\"all N document(s)\" line. Move it aside or declare the configuration\n" % n)
    for r in missing:
        sys.stderr.write(
            "%s.json: catalogue.json declares configuration %s and no document for it was "
            "assembled, so this sweep is a partial one\n" % (r, r))

    if stray or missing:
        return 3

    sys.stdout.write("%d document(s), one per declared configuration: %s\n"
                     % (len(found), ", ".join(found)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
