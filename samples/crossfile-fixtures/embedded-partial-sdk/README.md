# embedded-partial-sdk — VG-AISC-002 falsification (partially vendored SDK)

The normal shape of embedded work: part of a vendor SDK is vendored into the
tree (`sdk/cxd56_gpio.h`, quoted include, scanned) and the rest is on the
toolchain include path (`<cxd56_pwm.h>`, `<cxd56_adc.h>`, angled, not scanned).

`cxd56_pwm_start` and `cxd56_adc_read` are REAL functions. An earlier version of
the rule accepted any known prefix as evidence of a visible API surface, so the
vendored `cxd56_gpio_*` family made `cxd56` a "known namespace" and every real
call into a different `cxd56_*` family was accused of not existing — turning the
rule against exactly the projects it was written for.

The rule now requires the call's IMMEDIATE family (`cxd56_pwm`) to be the known
one, not merely an ancestor of it (`cxd56`).

Expected: zero `VG-AISC-002` findings.
