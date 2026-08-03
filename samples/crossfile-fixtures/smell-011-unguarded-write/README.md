# smell-011-unguarded-write/ — the positive that must stay `medium`

The same omission as `smell-011-unguarded-admin-route/`, with two differences
that are the point of having a second positive:

- nothing here names an administrator or an owner — not the route path, not the
  file — so the finding must come out `medium`, not `high`. A severity that is
  `high` for everything a rule emits is not a severity;
- all three guarded registrations sit in the one file being accused, so the
  convention is a file habit rather than a project decision, and the confidence
  must come out `low`.

**Expected: one `VG-SMELL-011` finding**, `medium` severity, `low` confidence.
