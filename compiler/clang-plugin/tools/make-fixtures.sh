#!/usr/bin/env bash
# Materialise the fixture set under ~/vg-lab/clang-ast-gate/fixtures.
#
# The fixtures live on the Linux filesystem, not in the repository, because
# interfaces.md §1 keeps measurement inputs out of `compiler/`. This script is
# the tracked, reproducible way to get them back: it is the fixture set, written
# once, with no state carried between runs.
set -euo pipefail

FIX="${1:-$HOME/vg-lab/clang-ast-gate/fixtures}"
rm -rf "$FIX"
mkdir -p "$FIX"

# --- Confirmed: a real, direct, non-macro call ------------------------------
cat > "$FIX/confirmed.c" <<'EOF'
#include <stdlib.h>

/* The Confirmed case, and nothing else. */
int run_report(const char *path)
{
  return system(path);
}

int main(void)
{
  return run_report("/bin/true");
}
EOF

# --- Rejected: the token exists only inside a comment and a string ----------
# Line 6 is the line the positive control rewrites into a real call. Keeping it
# a single self-contained statement is what makes that rewrite one `sed`.
cat > "$FIX/rejected.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>

static const char *doc(void)
{
  /* Not a call: system("id") is only described in this comment. */
  return "run system(\"id\") to see the effect";
}

int main(void)
{
  puts(doc());
  return 0;
}
EOF

# --- Refined: macro alias and function-like macro ---------------------------
cat > "$FIX/refined_macro.c" <<'EOF'
#include <stdlib.h>

#define SHELL system
#define RUN(cmd) system(cmd)

int via_alias(void)
{
  return SHELL("/bin/true");
}

int via_wrapper(void)
{
  return RUN("/bin/true");
}

int main(void)
{
  return via_alias() + via_wrapper();
}
EOF

# --- Refined: the address is taken here, the call is spelled elsewhere ------
cat > "$FIX/refined_fnptr.c" <<'EOF'
#include <stdlib.h>

typedef int (*runner_t)(const char *);

static runner_t g_run = system;

int main(void)
{
  return g_run("/bin/true");
}
EOF

# --- Rejected: declared and never called; and preprocessed out --------------
cat > "$FIX/rejected_more.c" <<'EOF'
#include <stdio.h>

extern int system(const char *cmd);

int main(void)
{
#if 0
  system("id");
#endif
  puts("nothing runs");
  return 0;
}
EOF

# --- Both classes in ONE file, so a verdict is provably per-location --------
cat > "$FIX/mixed.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>

static const char *why(void)
{
  return "we do not call system(cmd) from here";
}

int main(void)
{
  puts(why());
  return system("/bin/true");
}
EOF

# --- must-survive derivation, with the §4 control ---------------------------
cat > "$FIX/wipe.c" <<'EOF'
#include <string.h>

void fill_session(const char *in, char *out, unsigned n);

int login(const char *pw)
{
  char session_key[32];
  fill_session(pw, session_key, sizeof session_key);
  int ok = session_key[0] != 0;
  memset(session_key, 0, sizeof session_key);
  return ok;
}

/* Control, per interfaces.md §4: this wipe's result is read, so no optimiser
   is permitted to remove it. A run in which the control's count also fell to
   zero is a broken measurement, not a finding. */
int control(char *buf, unsigned n)
{
  memset(buf, 0, n);
  return buf[0];
}
EOF

# --- A call no lexical rule can see: the asm label redirects it -------------
cat > "$FIX/astonly_alias.c" <<'EOF'
extern int shell_out(const char *cmd) __asm__("system");

int main(void)
{
  return shell_out("/bin/true");
}
EOF

echo "fixtures written to $FIX"
ls -1 "$FIX"
