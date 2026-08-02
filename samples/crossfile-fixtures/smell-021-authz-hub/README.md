# smell-021-authz-hub — POSITIVE for VG-SMELL-021

`src/security/authorize.ts` is the project's single authorization policy. It
answers "may this subject do this", and to answer it reaches into eight other
modules of the project: configuration, the database client, a cache, two
repositories, a feature-flag service, an audit log and a logger.

Every one of those eight is upstream of the decision. A change to the feature
flag service, or a cache that returns a stale role, changes who gets in without
the policy being edited — and all eight have to be initialised before the first
request is authorised, which is before almost anything else.

The project has exactly 24 analysable modules, so the policy depends on exactly
a third of it: the boundary of `MAX_PROJECT_SHARE_DENOMINATOR`. The counts are
asserted in the test so the fixture cannot drift across it silently.
