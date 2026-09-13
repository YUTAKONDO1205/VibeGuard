#!/usr/bin/env python3
"""The configurations catalogue.json declares, as `runId<TAB>opt` lines.

Exists as a file rather than as a `python3 -c` inside run-all.sh for one reason:
the two refusals below are the only thing standing between a catalogue edited
down to `-O0` and a lane that can never qualify, and a refusal buried in a shell
quoting context is a refusal nobody tests. `test/test_run_all_projection.py`
tests these three exits.

Exit codes, run-all.sh's own (interfaces.md section 7 assigns 5 to "the harness
could not be set up", which is what all three of these are):
  0  one line per declared configuration, in the order the catalogue lists them
  1  the catalogue could not be read or parsed
  1  the catalogue declares no configuration, or none at which an R2b cell can
     move -- run-all.sh turns either into its own exit 5

Why the r2bCanMove check lives here and not in check-meta.py: check-meta.py
refuses a SWEEP in which nothing on the survival axis actually moved, which is a
fact about a set of measurements. This is a fact about the TABLE -- that the
configurations it declares could not, even in principle, express the axis -- and
it is knowable before the first compile. Finding it out from a refused grade at
the end of a sweep is finding it out late.
"""

import json
import sys


def main(argv):
    if len(argv) != 1:
        sys.stderr.write("usage: read-configurations.py <catalogue.json>\n")
        return 1
    try:
        with open(argv[0], encoding="utf-8") as fh:
            cat = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write("could not read %s: %s\n" % (argv[0], exc))
        return 1

    configs = cat.get("configurations") or []
    if not configs:
        sys.stderr.write(
            "catalogue.json declares no configurations, so there is nothing to sweep\n")
        return 1

    for i, c in enumerate(configs):
        for key in ("runId", "opt"):
            if not isinstance(c.get(key), str) or not c[key]:
                sys.stderr.write(
                    "catalogue.json configurations[%d] has no %s\n" % (i, key))
                return 1
        if not isinstance(c.get("r2bCanMove"), bool):
            sys.stderr.write(
                "catalogue.json configurations[%d] (%s) has no r2bCanMove boolean. It is "
                "not optional: it is what says whether this configuration can express the "
                "survival axis at all, and a configuration that does not say is a "
                "configuration nobody decided about\n" % (i, c["runId"]))
            return 1

    if not any(c["r2bCanMove"] for c in configs):
        sys.stderr.write(
            "catalogue.json declares %d configuration(s) and not one of them carries "
            "r2bCanMove true, so no sweep it can produce would ever ask the instrument to "
            "tell PRESENT from LOST. check-meta.py refuses exactly that set (exit 3, the "
            "survival-axis fence), so this catalogue describes a lane that can never "
            "qualify\n" % len(configs))
        return 1

    ids = [c["runId"] for c in configs]
    if len(set(ids)) != len(ids):
        sys.stderr.write(
            "catalogue.json declares the same runId twice (%s); the second measurement "
            "would overwrite the first and the sweep would grade one document as two\n"
            % ", ".join(sorted(i for i in set(ids) if ids.count(i) > 1)))
        return 1

    for c in configs:
        sys.stdout.write("%s\t%s\n" % (c["runId"], c["opt"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
