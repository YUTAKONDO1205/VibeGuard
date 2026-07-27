# embedded-volatile-angled — VG-RTOS-003 negative case (declaration outside the scan)

The handler writes `tick_count`, `main` reads it, and the declaration they share
lives in `<board_shared.h>` — an angled include on the toolchain's search path,
which is not part of this project and is not in the scan.

Expected: zero findings.

Nothing here says whether the vendor's declaration carries `volatile`. The rule's
claim is always about a declaration it has READ; with no declaration in any
project header, there is nothing to make a claim about, and it stops before it
reaches any of the other guards.

The mirror image of this fixture is the one that would be a bug: firing on
"we could not find a declaration" would report every firmware file that shares a
variable through a vendor header, which is most of them. VG-AISC-002's module
comment records the same lesson from the other direction.
