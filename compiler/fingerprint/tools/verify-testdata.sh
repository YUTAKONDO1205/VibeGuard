#!/usr/bin/env bash
# Assemble every tracked testdata file with llvm-as, so that the pairs the
# normalisations are proved against are real IR rather than IR-shaped strings.
#
#   bash verify-testdata.sh [--allow-empty]
#
# A pair of files that llvm-as rejects can be made to "agree" by any parser bug
# at all, which would make the whole test suite a tautology. Exit 0 when every
# file assembles, 1 when one does not, 3 when there was nothing to check or
# llvm-as is absent.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$HERE/../testdata"
AS="${LLVM_AS:-llvm-as-18}"
ALLOW_EMPTY=0
[ "${1:-}" = "--allow-empty" ] && ALLOW_EMPTY=1

if ! command -v "$AS" >/dev/null 2>&1; then
  echo "verify-testdata: $AS not found -- failing rather than skipping" >&2
  echo "inputs=0 checked=0 skipped=0"
  exit 3
fi

inputs=0
checked=0
skipped=0
failed=0
for f in "$DATA"/*.ll.txt; do
  [ -e "$f" ] || continue
  inputs=$((inputs + 1))
  if "$AS" -o /dev/null "$f" 2>/tmp/vg-fp-llvm-as.err; then
    checked=$((checked + 1))
  else
    checked=$((checked + 1))
    failed=$((failed + 1))
    echo "REJECTED $(basename "$f")"
    sed 's/^/    /' /tmp/vg-fp-llvm-as.err
  fi
done

echo "inputs=$inputs checked=$checked skipped=$skipped"
if [ "$inputs" -eq 0 ] && [ "$ALLOW_EMPTY" -eq 0 ]; then
  echo "no inputs: refusing to report a clean scan"
  exit 3
fi
[ "$failed" -eq 0 ] || exit 1
exit 0
