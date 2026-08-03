# smell-030-neg-super-call — NEGATIVE for VG-SMELL-030 (condition 2)

`ReportGuard.hasPermission()` ends in `return true`. It is silent because the
statement before it is `if (!super.hasPermission(subject)) return false;`.

Two independent reasons, and the fixture is written so they can be told apart:

* the body is not ONE statement, so condition (c) fails on its own;
* the body delegates, which is the classification the test asserts —
  `classifyOverride` must say `delegates`, not `other`.

The second is what matters. A subclass calling the inherited decision is
EXTENDING the bequest, which is the behaviour the rule's remediation text asks
for; a rule that fired here would be reporting its own recommended fix.

`hasPermission` is a self-evident name, so family corroboration plays no part in
the silence and cannot be mistaken for the cause.
