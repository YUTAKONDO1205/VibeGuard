# two-sites/ — falsifies condition (c)

Exactly **two** inlined authorization checks, one in each of two controller
files, both inside real route handlers registered in `routes.ts`. Conditions (a)
multiple files, (b) inlined rather than delegated, and (d) handler code are all
satisfied — this is a genuine, if small, instance of the pattern. What fails is
condition **(c)**, "3 or more occurrences in the same project": two is below the
threshold. The threshold is not decoration. Two duplicated checks are how almost
every service that ever grows a second privileged endpoint looks for a while, and
firing on that would make the rule a tax on ordinary code rather than a signal
about scattered policy. This directory is the off-by-one guard: a rule that
counts `>= 2`, or that counts privileged route handlers instead of counting
inlined checks, or that counts the two files' four exported functions rather than
their two comparisons, fires here and must not.
