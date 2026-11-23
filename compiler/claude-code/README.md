# compiler/claude-code — a Claude Code hook and skill for wipes that `-O2` deletes

Two ways of putting this toolchain's wipe check in front of a model that writes
C, kept here because a measured four-condition comparison used both:

- **The hook** (`hook/`) is a Claude Code `PostToolUse` hook. After the model
  writes or edits a `.c` file, it compiles the file with clang-18 and gcc-13 at
  `-O2`, decides for every function whether a wipe statement was deleted, and
  when one was, exits 2 with two lines on stderr naming the function, the line,
  the statement and the compilers, and suggesting a way of writing it that
  `-O2` does not delete. Claude Code passes that stderr to the model inside a
  notice of its own, which names it as a `PostToolUse` hook and shows the
  hook's command line. The prompt does not mention the hook.
- **The skill** (`skill/secret-wipe-c/`) is a `SKILL.md` telling the model how
  to write a wipe the optimiser keeps, and `scripts/check_wipe.py`, which
  checks one function in a simpler way, for a model that can run commands.

Both speak Japanese: the hook's stderr lines and `statusMessage`, and the whole
of `SKILL.md`. The stderr lines (inside Claude Code's notice) and the text of
`SKILL.md` are what the model received in the measured runs, so they are kept
byte for byte (*Provenance*).
Python 3 standard library only, no network. "Kept" below always means that the
function's instruction sequence changed when the wipe was removed — never that
no secret is left in memory.

## What the hook does

Event `PostToolUse`, matcher `Write|Edit` (the two settings files). From the
input JSON it reads `tool_name`, `tool_input.file_path` (absolute for both
tools; `tool_response.filePath` as a fallback) and `cwd`.

1. A tool other than Write, Edit or MultiEdit, or a path that does not end in
   `.c`: exit 0, nothing printed, nothing compiled. Headers are not checked.
2. Find the wipe statements of every function defined at file scope with
   `check_wipe.find_spans`, so no function name is needed: statements marked
   `/* wipe */` if the function has any; otherwise a zero `memset`,
   `explicit_bzero`, `bzero`, `memset_s` or another name in
   `check_wipe.WIPE_FN`, a call to a function of the same file that contains
   one, a call through a volatile function pointer that holds one, and a loop
   storing zero in a function that mentions `volatile`. A zero fill followed by
   a use and then a second fill of the same object is taken as initialisation
   and left out. No wipe anywhere: exit 0, nothing compiled.
3. Compile the file (w), and per function the file with all of that function's
   wipe statements blanked (wo), to assembly with the flags of
   `../eval/ai-generated/lib/ablation-cell.mjs` — `-S -std=gnu11 -w
   -Wno-error=implicit-function-declaration -fcf-protection=none -O2` — plus
   `-I` for the file's own directory, by clang-18 and by gcc-13 as installed
   (Ubuntu's gcc-13 defines `_FORTIFY_SOURCE=3` when optimising; clang-18
   defines none). Both units get `ablation-cell.mjs`'s control function
   `vgctl_control`, whose `__builtin_memset` survives `-O2`.
4. Read each function twice. **Difference:** the instruction sequence, label
   numbers masked, is identical in w and wo: `ELIMINATED`. **Zero stores:**
   among the lines only w has, a call to a memset-family function, `rep stos`,
   a store of immediate 0, a store from a register zeroed in the same body, or
   another call. A difference with none of these is `DISAGREE`, unless the w
   body holds such a call or store elsewhere (an error path's identical wipe
   merged with this one): `SURVIVED`. When there is a difference and two or
   more wipe statements, each is also removed alone, and one whose removal
   leaves the sequence unchanged was deleted (`PARTIAL`: a memset on the error
   return beside an `explicit_bzero` on the normal one). A statement that reads
   as deleted is preprocessed with and without it (`-E -P`); equal output means
   it sat under a false `#if` (`INACTIVE`, not counted). A `static` function with a body in only one of w
   and wo is `NOT_EMITTED` (its wipe is checked in the caller). No control in
   w: `CONTROL_MISSING`.
5. File verdict, strongest first: `ELIMINATED` (any function, `PARTIAL`
   included) > `COMPILE_ERROR` > `UNDECIDED` > `SURVIVED` > `NO_WIPE`.

### Exit codes

| situation | exit | stderr (two lines on exit 2) |
|---|---|---|
| not Write/Edit, not `.c`, no wipe found, or every wipe kept by both compilers (or only in functions that are not emitted, or under a false `#if`) | 0 | nothing |
| a wipe deleted by either compiler, one path included | 2 | file, function, line, statement and compilers (up to three items); a suggested rewrite built from the statement (`explicit_bzero(key, sizeof(key));`, or for a helper call, the helper's `memset` to change) |
| the file does not compile | 2 | the first error line; the missing declaration or `#include` is what to fix |
| the readings do not decide (`DISAGREE`, not in the assembly, no control) | 2 | not checked, not necessarily a fault in the code; writing the wipe with `explicit_bzero` makes it checkable |
| input not JSON; the check cannot run (WSL distribution missing); a compiler not installed or past its 60 s | 2 | not checked; **not a fault in the code** |
| the file is missing; the hook's own timeout; the scan itself failed | 2 | not checked (timeout and scan failure: not necessarily a fault in the code) |

Exit 2 of a `PostToolUse` hook shows stderr to the model after the tool has
run; the stderr of exit 0 does not reach it. So the hook does not stay silent
about a check it could not make: a compile failure, an undecided reading and a
broken environment are all exit 2, and the environment messages say the code is
not at fault, so that the model does not keep rewriting a correct file. stderr
names the file relative to `cwd`, or by its base name when it lies outside
`cwd`, and a compiler's error line has the temporary copy's path replaced by
`<file>`.

The exception to "never exit 0 silently" is a wipe the scan does not recognise:
that file has "no wipe" and exits 0 (*What it cannot see*).

`wipe_core.py` runs alone too: `python3 wipe_core.py --json FILE.c [--cc
clang-18,gcc-13] [--opt -O2]` prints one JSON object (`"schema":
"wipe-core-v1"`) and exits 0 `SURVIVED`/`NO_WIPE`, 1 `ELIMINATED`, 2
`COMPILE_ERROR`, 3 `UNDECIDED`.

### Windows and Linux

On Windows (`os.name == 'nt'`) the scan of step 2 runs in the Windows
interpreter, and the compile runs in WSL: `wsl.exe -d <distro> -u <user> --exec
python3 <wipe_core.py> --json --cc <compilers> <file>`, paths translated to
`/mnt/<drive>/…`. Windows needs no compiler. Anywhere else the hook runs
`wipe_core.py` with its own interpreter and the compilers on `PATH`. The
measured sessions used the Windows form; the tests here run the other.

| variable | default | |
|---|---|---|
| `VG_WSL_DISTRO` | `Ubuntu-24.04` | Windows only |
| `VG_WSL_USER` | `root` | Windows only |
| `VG_HOOK_TIMEOUT` | `100` | seconds for the check; the settings give Claude Code 120, so the hook's own exit-2 message comes first |
| `VG_HOOK_CCS` | `clang-18,gcc-13` | compilers, comma-separated |
| `VG_HOOK_LOG` | unset | a file to append one JSON line per run to (tool, path, verdict, the `wipe_core` output, exit, stderr, ms) |

## Installing

Copy the three `.py` files of `hook/` into `.claude/hooks/vg_wipe/` of the
project, and merge one settings file into the project's `.claude/settings.json`:
`settings.project.json` (`"command": "python"`, for Windows) or
`settings.project.linux.json` (`"python3"`). Both use the exec form (`command`
plus `args`, no shell), name the hook
`${CLAUDE_PROJECT_DIR}/.claude/hooks/vg_wipe/vg_wipe_hook.py` and allow 120 s.
On Linux, `clang-18` and `gcc-13` must be on `PATH`; on Windows they, and
`python3`, must be in the WSL distribution.

The measured sessions did not load these two files: their runner put the hook
entry into a `--settings` argument (*Measured*). The files' shape is checked by
`test/test_hook_static.py`; their use in a session is not measured.

## The skill

`SKILL.md` (front matter `name: secret-wipe-c` and a `description`) tells the
model to wipe every region that held a secret on every return path, before
`free` for the heap; not to use a plain `memset`; to use `explicit_bzero`
(glibc 2.25 or later), `memset_s` where C11 Annex K exists, or else a byte loop
through a volatile pointer or a `memset` followed by an empty `asm volatile`
with a memory clobber; to mark the wipe line `/* wipe */`; to write every branch
of an `#if` the same way; and, when it can run commands, to check the result:

```sh
python3 scripts/check_wipe.py <file.c> <function> [--cc gcc,clang] [--opt -O2] [--cflags "..."] [--json]
```

`check_wipe.py` finds the wipe statements of that one function (as in step 2),
removes all of them at once, compiles both versions with `<cc> -std=gnu11 -w
<opt> <cflags> -S`, and compares the function's normalised instruction
sequence. Exit 0: kept by every compiler named in `--cc` that is installed — a
compiler that is not installed is skipped without a word, so exit 0 can rest on
one compiler (measured 2026-11-23: `--cc gcc-13,clang-99` on `safe.c` exits 0;
with only `clang-99`, 2). 1: deleted by one. 2: no wipe found, function not
found, a compile error, the function not in the assembly, or no named compiler
installed. The hook differs here: a missing compiler is exit 2. It is
simpler than the hook's reading, and the difference shows on two of the hook's
cases (measured, `test/test_hook_clang_gcc.py`): it removes every wipe together,
so `partial.c`'s memset deleted on the error return reads as kept behind the
`explicit_bzero` kept on the normal return (exit 0, where the hook reports line
13); and it compiles a copy in a temporary directory without `-I`, so
`withheader.c`'s `#include "keyutil.h"` fails (exit 2). It has no control
function and no zero-store reading, and its default compilers are `gcc,clang`.

The directory has the layout of a Claude Code skill, but it was never measured
installed as one: both measured generations passed the text of `SKILL.md` with
`--append-system-prompt-file`, and neither gave the model a tool that runs
commands, so no model ran `check_wipe.py` in any measurement.

## Provenance

Copied from the lab copies the measurements used; the lab notes are kept outside
this repository.

| file | sha256 of the lab copy | this copy |
|---|---|---|
| `hook/vg_wipe_hook.py` | `0485cdabb5eb8efc…` | identical |
| `hook/wipe_core.py` | `531183f9e57e5878…` | `398cef6cf94bcc0f…`: three lines edited (below) |
| `hook/check_wipe.py` | `c532a1bfd845bd88…` | identical |
| `hook/settings.project.json` | `83febbcb9f4bfcb5…` | identical |
| `hook/settings.project.linux.json` | `dde03558120bccd5…` | identical |
| `skill/secret-wipe-c/SKILL.md` | `dc844ccdf3412472…` | identical |
| `skill/secret-wipe-c/scripts/check_wipe.py` | `c532a1bfd845bd88…` | identical, and the same file as `hook/check_wipe.py` |
| `test/cases/*` (12 files) | | identical to the inputs of the measured unit tests |

The full digests, the twelve inputs' included, are in
`test/test_hook_static.py` (`PROVENANCE`), which fails when a file changes
without its row. The three edits to `wipe_core.py`, made
for publication, change nothing any code reads:

- line 17, in the docstring: the out-of-repository path in front of the name of
  the lab reading it was copied from (`asm_read2.mjs`) is gone;
- lines 201 and 329: the `schema` value of the printed JSON had a lab name as
  its prefix; it is now `wipe-core-v1`. The hook only copies that object into
  its log.

Not copied: the settings file for `claude --settings` (absolute local paths);
the lab's test runners (they wrote their results beside themselves); the
359-file validation script (it reads corpora outside this repository). The two
files of `test/` are new.

## Measured

Lab measurements of 2026-11-05, and of 2026-10-02 for the two sections on the
skill's own evaluation (x86-64, WSL Ubuntu 24.04, clang 18.1.3, gcc 13.3.0),
every number re-read from the lab's data files for this README. What was run
again on 2026-11-23 says so.

### Unit tests and time per check

The hook's 17 cases (the 16 rows of `test/test_hook_clang_gcc.py` and a WSL
distribution that does not exist) passed 17/17 on Windows (Python 3.14.3, the
hook calling WSL) and 16/16 in WSL (Python 3.12.3, where the WSL case does not
apply). The same hook entry with absolute paths (the `claude --settings` file
that is not copied here), started without a shell as Claude Code starts it,
passed 4/4 (the deleting case by Write and by Edit exit 2, `safe.c` and a `.py`
exit 0).

One hook run, wall clock, from those runs: 0.46–1.0 s on Windows (the 9 runs
that compiled, WSL start-up included) and 0.55–0.97 s in WSL; 0.13–0.15 s and
0.16–0.23 s for the 6 runs that returned before compiling. Over the 359 files
below, `wipe_core` alone took a median of 399 ms and at most 3,253 ms per file,
four files at a time.

Run again on 2026-11-23: `test/test_hook_static.py` 17/17 on Windows (Python
3.14.3) and in WSL (Python 3.12.3); `test/test_hook_clang_gcc.py` 26/26 in WSL
(clang 18.1.3, gcc 13.3.0). Seven mutations of a copy — a deletion exiting 0,
no one-at-a-time reading, bad input exiting 0, an absolute path in a settings
file, the two `check_wipe.py` differing, `.h` checked, no `-I` — each failed at
least one of the two suites, and so does an edited test input (`deleted.c`
with `explicit_bzero`: the static suite's digest check).

### The hook's reading against an earlier verdict (359 files)

`wipe_core.py` on the stack-wipe files of the r4 L corpus (four models, ten
tasks; 360 listed, one with no file), against that corpus's own `-O2` verdicts
after its two corrected files:

| earlier verdict → hook's reading | clang-18 | gcc-13 |
|---|---|---|
| deleted → deleted | **51** | **51** |
| deleted → anything else (missed) | **0** | **0** |
| kept → kept | 280 | 282 |
| kept → deleted | 2 | 2 |
| kept → no wipe | 0 | 1 |
| no wipe → no wipe | 23 | 23 |
| compile error → compile error / no wipe | 2 / 1 | — |

The four "kept → deleted" cells (clang-18 `haiku_E_privkey_r1` and
`haiku_S_token_r2`, gcc-13 `haiku_E_privkey_r1` and `sonnet_N_pwverify_r3`) are
deletions on one path, found by the one-at-a-time reading. The lab notes record
a hand reading of `haiku_E_privkey_r1` with both compilers (no zero store on the
path where reading the key file failed) and of `sonnet_N_pwverify_r3` with
gcc-13 (the only zero store is a `rep stosq` after the hash; the final wipes of
`computed` and `expected` are gone). The gcc-13 "no wipe" is
`sonnet_E_aeskey_r3`, wiped through a typedef'd volatile function pointer the
scan does not recognise: exit 0 is right there, for the wrong reason. The
clang-18 "compile error → no wipe" is the same file, which clang-18 rejects
(incompatible function pointer types); the hook compiles nothing when it finds
no wipe, so it exits 0 there as well. The first
run left 13 clang-18 and 6 gcc-13 cells undecided; the reading was corrected
(an identical wipe on another path merged with the removed one, `static`
helpers present on one side only, statements under a false `#if`) and run
again with 0 undecided; a later run, with `-I`, gave the same per-compiler
reading for all 359 files (the lab notes record it as the third and the table
is from it; the file times do not show which of the two ran first).

### `check_wipe.py` against the same kind of verdict (336 files)

The skill's own evaluation, 336 files of the same corpus × 2 compilers at
`-O2`: deleted → deleted 98, kept → kept 566, kept → deleted 4 (two files whose
earlier verdict had removed an initialising memset together with the wipe),
kept → no wipe found 1, compile error → undecided 2, compile error → no wipe 1.
Missed: 0.

### The four-condition generation

From the lab's job list and runner:

- The ten stack-wipe tasks with the prompt of r4 L's no-extra-instruction arm,
  only the output rule changed to "write the whole file to `<function>.c` in
  the working folder with the Write tool". The prompt does not mention the hook.
- **T0** tools only (Write, Edit, Read). **T1** adds the skill: a one-line
  preface plus `SKILL.md`, passed with `--append-system-prompt-file` (the text
  of the earlier skill run, sha256 prefix `0525489459cdba6f`). **T2** adds the
  hook: the job's `--settings` JSON carries a `PostToolUse` entry (matcher
  `Write|Edit`, the Windows Python running copies of the three `.py` files
  whose digests were checked against the measured copies of *Provenance*,
  timeout 120, no `statusMessage`) and `VG_HOOK_LOG` names a file outside the
  working folder. On exit 2 the model received the stderr inside Claude Code's
  notice naming the hook and its command line: 48 such notices in 42 of the
  480 transcripts. **T3** adds both. No condition had a tool that runs
  commands.
- Every job: `claude -p --model <id> --tools "Write,Edit,Read"
  --permission-mode acceptEdits --setting-sources "" --strict-mcp-config
  --disable-slash-commands --settings <json> --output-format stream-json
  --verbose --include-hook-events --max-turns 16`, the settings JSON also
  setting `autoMemoryEnabled` false and excluding `CLAUDE.md`; a fresh empty
  working folder; Claude Code 2.1.318 in all 480 runs.
- Models `claude-haiku-4-5-20251001`, `claude-sonnet-5` and `claude-opus-5-5`,
  three runs per task: 90 per condition. `claude-fable-5-1` was asked too and
  is not in the table: 37 of its runs (T0 20, T2 17) were answered, after two
  safety stops, by a different model (`claude-opus-4-8` alone in 36, both
  models in one), which leaves it 10,
  30, 13 and 30 valid runs and a denominator that differs by condition. The
  rule to report the three models was written before the files were compiled
  and classified. No wipe was deleted in its valid runs.
- The last version of each file, classified at `-O2` with clang-18 and gcc-13
  by `../eval/ai-generated/lib/ablation-cell.mjs`: no wipe; a form that is not
  deleted (`explicit_bzero`, volatile, …); memset kept; memset deleted by
  either compiler. 7 files were decided by hand, each an initialising memset
  read as a wipe: 5 in T0 moved to deleted, 1 in T0 and 1 in T2 to no wipe.
  For 21 more the wipe statement was supplied by hand, verbatim, because it
  is a macro call (`SECURE_WIPE(…)`, `SECRET_WIPE(…)`) that the classifier's
  span finder does not see; those files were then compiled and classified
  like the rest. 11 of them are in the table (T1 5, T3 6, all
  `claude-opus-5-5`) and 10 are `claude-fable-5-1`'s. Without them, T1 and
  T3 would show those files as having no wipe.

| condition | what the model had | memset deleted | no wipe | not-deleted form | memset kept |
|---|---|---|---|---|---|
| T0 | tools only | **30/90** | **28/90** | 32 | 0 |
| T1 | skill text in the system prompt | **0/90** | **0/90** | 88 | 2 |
| T2 | hook in `--settings` | **0/90** | **26/90** | 63 | 1 |
| T3 | both | **0/90** | **0/90** | 90 | 0 |

The skill alone already gave 0/90 on both counts, so **the value the hook adds
over the skill was not established by this comparison**; the hook's part is to
check the output of a model that does not follow the skill. The hook does not
react to a missing wipe: T2 left 26 files without one, against T0's 28. The
verdict is taken at `-O2`, the level the hook checks; no other level or flag
setting was measured.

### Hook firing in T2 and T3

From the hook's log, three models, 90 jobs per condition:

| | jobs where the hook ran | hook runs | exit 2 returned | jobs that got an exit 2 | of those, last reading kept | jobs whose last reading was "no wipe" |
|---|---|---|---|---|---|---|
| T2 | 90 | 124 | 33 | 31 | 31 | 25 |
| T3 | 90 | 93 | 2 | 2 | 2 | 0 |

T0 and T1 have no hook runs, as configured. Jobs that got an exit 2, by model:
T2 haiku 9, sonnet 21, opus 1; T3 opus 2. Every one of them ended with the hook
reading the last version as kept; none ended by dropping the wipe. The 25 T2
jobs whose last reading was "no wipe" are the table's 26 less one file whose
only memset fills the buffer before use: the hand count calls it no wipe, the
hook's reading a kept one.

### An earlier skill run, without tools

The skill's own earlier evaluation (the same four model ids, `claude-fable-5-1`
included, the same ten tasks, no tools at all, `SKILL.md` in the system
prompt): 118 of 120
runs returned code — the lab notes record that the other 2 returned text that
tried to run the check step — and of the 118, memset deleted 0, no wipe 0, all
118 marked `/* wipe */`, 116 using `explicit_bzero`, 2 memset kept. Without the
skill, 119 measured files of 120 (one excluded): memset deleted 32, no wipe 22.

## What it cannot see

From the lab's own list of limits, and two rows measured here:

- Only `-O2` with the fixed flags above. The user's build settings (`-O3`,
  LTO, `-D_FORTIFY_SOURCE`, …) are not looked at.
- A wipe the scan does not recognise is "no wipe", exit 0. Measured on
  2026-11-23 in the shape of `deleted.c`: `memset(key, '\0', …)`,
  `__builtin_memset`, a plain (not volatile) loop and a macro without
  `/* wipe */` were each deleted by clang-18 and gcc-13 at `-O2`, and the hook
  said nothing (the scan side is pinned in `test/test_hook_static.py`). A
  typedef'd volatile function pointer was kept by both: exit 0 again, right for
  the wrong reason.
- Initialisation and wipe are told apart by statement order, so an error-path
  memset of an array that is used later (`sonnet_N_pwverify_r3`, lines 28, 41
  and 46) is not counted as a wipe.
- Header files, and tools other than Write and Edit (the matcher leaves out
  MultiEdit).
- `PostToolUse` cannot stop the tool: the file stays as written, and if the
  model does not fix it, the wipe stays deleted.
- The check of the reading covers 359 files of four models and ten tasks.
- x86-64 Linux, clang 18.1.3, gcc 13.3.0, one vendor's models.
- `check_wipe.py` looks at the one function it is given: a wipe inside a helper
  needs the helper's name too; and it has the two differences above.

## Not measured

- What the hook adds over the skill (above).
- A model that can run commands, and therefore `check_wipe.py` in a session.
- The skill installed as a Claude Code skill rather than given as
  system-prompt text.
- The two shipped settings files in a session, and the hook's Linux form in a
  session: the measured sessions ran the Windows form through WSL.
- The hook at other optimisation levels, `_FORTIFY_SOURCE` settings or
  compiler versions; other languages.
- How much the hook slows a session (only the per-run times above).
