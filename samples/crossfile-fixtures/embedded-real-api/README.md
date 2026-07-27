# embedded-real-api — VG-AISC-002 falsification corpus

Every call here is legitimate. It exists to pin the two ways the rule could
become unshippable:

- Calls into the real `cxd56_gpio_*` family, all four declared in the header.
- Standard-library calls (`memset`, `memcpy`, `snprintf`, `printf`) whose
  declarations live in system headers the scan cannot resolve. The "absence"
  formulation of this rule reports all four; the known-namespace formulation
  reports none, because no project header declares a `mem_*` or `snprintf_*`
  family and so those names belong to no namespace the project can see.

Expected: zero `VG-AISC-002` findings.
