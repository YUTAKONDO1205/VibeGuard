# smell-013-neg-test-path

A test harness that mounts its own router and decides privilege inline is
describing a test, not the service. `isTestPath` from the shared lexicon is the
exclusion, and it is the same one every rule in this directory applies.

The guard convention lives in shipped code, so the premise holds and the only
thing keeping the rule quiet is the path of the offending handler.
