// Synthetic envelopes for derive-fallback-table, as data rather than as files.
//
// Every one is HAND-WRITTEN. None contains a measured value, a real subject name
// or a real property id, and none should ever be quoted as a result. The names
// are `p.alpha`, `s-a` and so on precisely so that a number copied out of a
// test and into a paper is obviously wrong.
//
// They exist because the real envelope exercises only some of the branches. A
// fixture is the only way to make the generator prove what it does with a
// candidate set that was fully measured and fully lost, with a property whose
// second subject was never measured, with an ABSENT candidate, with a positive
// control sitting on top of a real measurement, with an opt level the ladder
// does not rank, and with an envelope that has nothing usable in it at all.
//
// WHY THIS IS A MODULE AND NOT A DIRECTORY OF .json FILES
//
// scripts/check-packaging-invariants.mjs refuses any committable path under
// `compiler/` carrying a `fixtures/` or `_results/` segment: measurement inputs
// and outputs stay on the side that produces them, because they carry absolute
// paths and per-machine toolchain digests. These envelopes carry neither — but
// the guard is a path rule on purpose, and "this one is synthetic, honest" is
// exactly what would be said about the first real measurement to land there.
// The rest of compiler/driver/test/ already builds its inputs in code
// (`observer-fixture.mjs`, `helpers.mjs`) and commits no data directory, so
// this follows the convention rather than carving an exception out of a guard.
//
//   name                       what it forces
//   -------------------------  ----------------------------------------------
//   fallback-simple            one row, one subject, fallback to the highest surviving opt level
//   no-safe-target             every candidate measured and every one LOST, plus an already-weakest row
//   not-observed               one candidate broken, one missing -> not-observed, never no-safe-target
//   control-cells              a ctl= control at the same (subject, config) as a real cell, contradicting it
//   all-broken                 not one measurement === "OK" cell -> exit 3, no table
//   lost-control-cell          a LOST cell no row can account for -> exit 2, no table
//   lost-under-broken-instrument  a LOST reported by a broken instrument -> no row, no exit 2
//   two-subjects               a property whose second subject is unmeasured, beside one where both are
//   measured-absent            the candidate is ABSENT, not LOST -- the two must not merge
//   lto-weakening              the only surviving target needs LTO dropped, which is not a fallback
//   non-monotonic              PRESENT at a higher opt level than a LOST one; recorded, not smoothed
//   opt-off-ladder             LOST at -Os, which the ladder does not rank -> not-observed

/** name -> envelope document. Frozen so a test cannot mutate another test's input. */
export const ENVELOPES = Object.freeze({
  "all-broken": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "Not one cell carries measurement OK. There is no table to write and no score to report.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 3
    },
    "cells": [
      {
        "cellId": "s-a+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "NOT_OBSERVED",
        "measurement": "BROKEN_MEASUREMENT",
        "controlHeld": null
      },
      {
        "cellId": "s-a+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "NOT_OBSERVED",
        "measurement": "BROKEN_MEASUREMENT",
        "controlHeld": null
      },
      {
        "cellId": "s-a+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "NOT_OBSERVED",
        "measurement": "UNSUPPORTED",
        "controlHeld": null
      }
    ]
  },
  "control-cells": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "Three positive controls sit at the same (subject, config) coordinates as real cells. The pce2 control contradicts the real -O1 measurement: if a control were allowed to overwrite it, the row would flip from fallback to not-observed. The third control reports a healthy PRESENT, which means it did not control anything, and must be called out.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 6
    },
    "cells": [
      {
        "cellId": "s-a+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O0+ndebug=0+lto=none+target=host+free=0+ctl=pce3-control-that-did-not-trip",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O1+ndebug=0+lto=none+target=host+free=0+ctl=pce2-observer-unregistered",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "NOT_OBSERVED",
        "measurement": "BROKEN_MEASUREMENT",
        "controlHeld": null
      },
      {
        "cellId": "s-a+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O2+ndebug=0+lto=none+target=host+free=0+ctl=pce1-plugin-absent",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "NOT_OBSERVED",
        "measurement": "UNSUPPORTED",
        "controlHeld": null
      }
    ]
  },
  "fallback-simple": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "One subject, one loss, a measured survivor one step down.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 3
    },
    "cells": [
      {
        "cellId": "s-a+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "lost-control-cell": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "A positive control reports LOST. Controls are excluded from the search population, so no row can account for it -- and a loss no row accounts for must stop the run, not be dropped.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 4
    },
    "cells": [
      {
        "cellId": "s-a+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-a+opt=O1+ndebug=0+lto=none+target=host+free=0+ctl=pce1-plugin-absent",
        "propertyId": "p.alpha",
        "subject": "s-a",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "lost-under-broken-instrument": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "A LOST reported with measurement=BROKEN_MEASUREMENT. It is a statement about the instrument, so it gets no row -- and must not trip the every-LOST-cell-is-accounted-for invariant either.",
    "axes": {
      "freestanding": [
        false
      ],
      "lto": [
        "none"
      ],
      "ndebug": [
        false
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host"
      ]
    },
    "counts": {
      "cells": 3
    },
    "cells": [
      {
        "cellId": "s-b+opt=O2+broken",
        "propertyId": "p.beta",
        "subject": "s-b",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "BROKEN_MEASUREMENT",
        "controlHeld": null
      },
      {
        "cellId": "s-b+opt=O3",
        "propertyId": "p.beta",
        "subject": "s-b",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O3",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-b+opt=O0",
        "propertyId": "p.beta",
        "subject": "s-b",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "lto-weakening": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "Survival is available at the same -O2 with link-time optimisation switched off. The preference order takes it, and the row is flagged because the driver profile cannot express a link-mode change.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 2
    },
    "cells": [
      {
        "cellId": "s-l+opt=O2+ndebug=0+lto=thin-prelink+target=host+free=0",
        "propertyId": "p.eta",
        "subject": "s-l",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "thin-prelink",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-l+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.eta",
        "subject": "s-l",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "measured-absent": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "The only candidate has the property ABSENT: observed, and observed not to be there. That is neither a survival nor a loss.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 2
    },
    "cells": [
      {
        "cellId": "s-z+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.zeta",
        "subject": "s-z",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "ABSENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-z+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.zeta",
        "subject": "s-z",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "no-safe-target": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "Every candidate was compiled and every candidate lost the property. The -O0 row has no candidates at all.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 3
    },
    "cells": [
      {
        "cellId": "s-b+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.beta",
        "subject": "s-b",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-b+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.beta",
        "subject": "s-b",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-b+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.beta",
        "subject": "s-b",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "non-monotonic": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "LOST at -O1 but PRESENT at -O2. Weakening is not a total order here, and the table says so instead of averaging it away.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 4
    },
    "cells": [
      {
        "cellId": "s-n+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.theta",
        "subject": "s-n",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-n+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.theta",
        "subject": "s-n",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-n+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.theta",
        "subject": "s-n",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-n+opt=O3+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.theta",
        "subject": "s-n",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O3",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "not-observed": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "The instrument failed at -O1 and -O0 was never run. Nothing here supports \"no safe target\".",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 2
    },
    "cells": [
      {
        "cellId": "s-g+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.gamma",
        "subject": "s-g",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "NOT_OBSERVED",
        "measurement": "BROKEN_MEASUREMENT",
        "controlHeld": null
      },
      {
        "cellId": "s-g+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.gamma",
        "subject": "s-g",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "opt-off-ladder": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "LOST at -Os. The ladder ranks -O0..-O3 only, so nothing weaker can be named. Not knowing what is weaker is not the same as knowing nothing weaker holds.",
    "axes": {
      "freestanding": [
        false
      ],
      "lto": [
        "none"
      ],
      "ndebug": [
        false
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3",
        "-Os"
      ],
      "target": [
        "host"
      ]
    },
    "counts": {
      "cells": 2
    },
    "cells": [
      {
        "cellId": "s-o+opt=Os",
        "propertyId": "p.omega",
        "subject": "s-o",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-Os",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "s-o+opt=O0",
        "propertyId": "p.omega",
        "subject": "s-o",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
  "two-subjects": {
    "schemaVersion": "security-configuration-envelope-v0",
    "component": "FixtureOnly",
    "note": "p.delta is carried by two programs and the second was only ever measured at -O2; keying by property alone would fall back to -O1 on the strength of the first. p.epsilon has both subjects measured everywhere and does resolve.",
    "axes": {
      "freestanding": [
        false,
        true
      ],
      "lto": [
        "full-prelink",
        "none",
        "thin-prelink"
      ],
      "ndebug": [
        false,
        true
      ],
      "opt": [
        "-O0",
        "-O1",
        "-O2",
        "-O3"
      ],
      "target": [
        "host",
        "other-target"
      ]
    },
    "counts": {
      "cells": 10
    },
    "cells": [
      {
        "cellId": "d-folded+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.delta",
        "subject": "d-folded",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "d-folded+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.delta",
        "subject": "d-folded",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "d-folded+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.delta",
        "subject": "d-folded",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "d-live+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.delta",
        "subject": "d-live",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "e-one+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.epsilon",
        "subject": "e-one",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "e-one+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.epsilon",
        "subject": "e-one",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "e-one+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.epsilon",
        "subject": "e-one",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "LOST",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "e-two+opt=O0+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.epsilon",
        "subject": "e-two",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O0",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "e-two+opt=O1+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.epsilon",
        "subject": "e-two",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O1",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      },
      {
        "cellId": "e-two+opt=O2+ndebug=0+lto=none+target=host+free=0",
        "propertyId": "p.epsilon",
        "subject": "e-two",
        "config": {
          "cc": "cc-fixture",
          "freestanding": false,
          "lto": "none",
          "ndebug": false,
          "opt": "-O2",
          "target": "host"
        },
        "state": "PRESENT",
        "measurement": "OK",
        "controlHeld": true
      }
    ]
  },
});
