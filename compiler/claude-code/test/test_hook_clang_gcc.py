#!/usr/bin/env python3
"""Tests of the Claude Code hook and of the skill's check_wipe.py that compile:
clang-18 and gcc-13 must be on PATH.

The hook is run the way Claude Code runs it -- a PostToolUse input on stdin, no
shell -- in its Linux mode, where it runs wipe_core.py with its own interpreter
instead of going through WSL. The cases and the expected exit codes and stderr
are the hook's unit-test table from the measurement (README.md, "Measured"),
less the one row that only means something on Windows (a WSL distribution that
does not exist; test_hook_static.py covers that path without a compiler).

    python3 compiler/claude-code/test/test_hook_clang_gcc.py

Run as a file: the directory name is not a Python package name. Like the other
toolchain suites of this tree, a missing clang-18 or gcc-13 is a failure, not
a skip.
On a platform that is not POSIX the suite is skipped: the hook would call WSL
there, which is not what is tested here. Nothing is written into the
repository: no bytecode, and the hook's log goes to a temporary directory.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..'))
HOOK = os.path.join(ROOT, 'hook', 'vg_wipe_hook.py')
CHECK_WIPE = os.path.join(ROOT, 'skill', 'secret-wipe-c', 'scripts', 'check_wipe.py')
CASES = os.path.join(HERE, 'cases')
COMPILERS = ('clang-18', 'gcc-13')


def C(name):
    return os.path.join(CASES, name)


def event(tool, path):
    ti = {'file_path': path}
    if tool == 'Write':
        ti['content'] = ''
        if os.path.isfile(path):
            with open(path, encoding='utf-8') as f:
                ti['content'] = f.read()
        resp = {'filePath': path, 'type': 'create'}
    else:
        ti.update({'old_string': 'x', 'new_string': 'y', 'replace_all': False})
        resp = {'filePath': path}
    return {'session_id': 'test-session', 'transcript_path': 'test-transcript.jsonl', 'cwd': CASES,
            'permission_mode': 'default', 'hook_event_name': 'PostToolUse', 'tool_name': tool,
            'tool_input': ti, 'tool_response': resp, 'tool_use_id': 'test-toolu-0001', 'duration_ms': 1}


# (name, stdin, expected exit, regex the stderr must match (re.S), extra environment).
# Copied from the measured table; the regexes are its regexes.
TESTS = [
    ('deleted by -O2 (memset, Write)', event('Write', C('deleted.c')), 2,
     r'関数 encrypt_once の 12 行目 `memset\(key, 0, sizeof\(key\)\);`（clang-18・gcc-13）.*\n.*explicit_bzero\(key, sizeof\(key\)\);', {}),
    ('deleted by -O2 (Edit)', event('Edit', C('deleted.c')), 2, r'12 行目', {}),
    ('kept (explicit_bzero)', event('Write', C('safe.c')), 0, r'^$', {}),
    ('kept (volatile function pointer)', event('Write', C('vfnptr.c')), 0, r'^$', {}),
    ('one path deleted (memset on the error return)', event('Write', C('partial.c')), 2, r'関数 verify_pin の 13 行目', {}),
    ('a memset under a false #ifdef is not read as deleted', event('Write', C('ifdef.c')), 0, r'^$', {}),
    ('includes a header from its own directory (deleted)', event('Write', C('withheader.c')), 2, r'関数 encrypt_once の 9 行目', {}),
    ('wiped through a static helper that is inlined (deleted)', event('Write', C('helper.c')), 2,
     r'関数 send_session_token の 16 行目 `wipe\(tok, sizeof\(tok\)\);`.*\n.*wipe の中の `memset', {}),
    ('not C (.py)', event('Write', C('notc.py')), 0, r'^$', {}),
    ('a C header (.h, not checked)', event('Write', C('header.h')), 0, r'^$', {}),
    ('C that does not compile', event('Write', C('broken.c')), 2, r'コンパイルできず.*undefined_type_t', {}),
    ('C without a wipe (not compiled)', event('Write', C('nowipe.c')), 0, r'^$', {}),
    ('a tool other than Write and Edit (Read)', dict(event('Write', C('deleted.c')), tool_name='Read'), 0, r'^$', {}),
    ('the file does not exist', event('Write', C('missing.c')), 2, r'見つからず', {}),
    ('the input is not JSON', 'this is not json', 2, r'入力（JSON）を読めず', {}),
    ('the compilers are not installed (environment)', event('Write', C('deleted.c')), 2,
     r'環境が整っておらず.*NOT_INSTALLED.*\n.*コードの誤りではない', {'VG_HOOK_CCS': 'clang-99,gcc-99'}),
]

# What the hook's log says for the rows that reach wipe_core, by case file.
LOGGED_VERDICT = {'deleted.c': 'ELIMINATED', 'safe.c': 'SURVIVED', 'vfnptr.c': 'SURVIVED', 'partial.c': 'ELIMINATED',
                  'ifdef.c': 'SURVIVED', 'withheader.c': 'ELIMINATED', 'helper.c': 'ELIMINATED', 'broken.c': 'COMPILE_ERROR'}

# The skill's check_wipe.py on the same cases: (file, function, expected exit).
# partial.c and withheader.c are where it and the hook differ. check_wipe.py
# removes every wipe of the function at once, so a memset deleted on one path
# hides behind an explicit_bzero kept on another (exit 0, where the hook says
# 13 行目); and it compiles a copy in a temporary directory without -I, so a
# header next to the file is not found (exit 2).
CHECK_WIPE_CASES = [
    ('deleted.c', 'encrypt_once', 1),
    ('helper.c', 'send_session_token', 1),
    ('safe.c', 'encrypt_once', 0),
    ('vfnptr.c', 'encrypt_once', 0),
    ('ifdef.c', 'encrypt_once', 0),
    ('partial.c', 'verify_pin', 0),
    ('withheader.c', 'encrypt_once', 2),
    ('nowipe.c', 'add', 2),
    ('deleted.c', 'no_such_function', 2),
    ('broken.c', 'encrypt_once', 2),
]
CHECK_WIPE_RESULT = {0: 'SURVIVED', 1: 'ELIMINATED'}


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('VG_', 'WPIN_'))}
    env.update(PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1', **extra)
    return env


@unittest.skipUnless(os.name == 'posix', 'the hook calls WSL on Windows; its Linux mode is what is tested here')
class Toolchain(unittest.TestCase):
    def setUp(self):
        missing = [cc for cc in COMPILERS if shutil.which(cc) is None]
        if missing:
            self.fail('not on PATH: ' + ', '.join(missing) + ' (this suite compiles; it does not skip)')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)


class HookLinuxMode(Toolchain):
    """One test per row of TESTS (methods added below the class)."""

    def run_row(self, inp, want, pat, extra):
        log = os.path.join(self.tmp.name, 'hook-log.jsonl')
        data = inp if isinstance(inp, str) else json.dumps(inp, ensure_ascii=False)
        r = subprocess.run([sys.executable, '-B', HOOK], input=data.encode('utf-8'), capture_output=True,
                           env=clean_env(VG_HOOK_LOG=log, **extra), cwd=self.tmp.name, timeout=300)
        err = r.stderr.decode('utf-8', errors='replace').rstrip('\n')
        self.assertEqual(r.returncode, want, err)
        self.assertRegex(err, re.compile(pat, re.S))
        self.assertEqual(r.stdout, b'')
        # Two lines on exit 2, nothing on exit 0.
        self.assertEqual(len(err.split('\n')) if err else 0, 2 if want == 2 else 0, err)
        # One log line per run, outside the repository, with the same exit.
        with open(log, encoding='utf-8') as f:
            (line,) = f.read().splitlines()
        rec = json.loads(line)
        self.assertEqual(rec['exit'], want)
        base = None if isinstance(inp, str) else os.path.basename(inp['tool_input']['file_path'])
        if base in LOGGED_VERDICT and inp['tool_name'] in ('Write', 'Edit') and not extra:
            self.assertEqual(rec['result'], LOGGED_VERDICT[base])


def _hook_test(inp, want, pat, extra):
    return lambda self: self.run_row(inp, want, pat, extra)


for _i, (_name, _inp, _want, _pat, _extra) in enumerate(TESTS, 1):
    _m = _hook_test(_inp, _want, _pat, _extra)
    _m.__doc__ = _name
    setattr(HookLinuxMode, f'test_hook_{_i:02d}_' + re.sub(r'\W+', '_', _name.split(' (')[0]).strip('_').lower(), _m)


class SkillCheckWipe(Toolchain):
    """One test per row of CHECK_WIPE_CASES (methods added below the class)."""

    def run_case(self, f, fn, want):
        r = subprocess.run([sys.executable, '-B', CHECK_WIPE, C(f), fn, '--cc', ','.join(COMPILERS), '--json'],
                           capture_output=True, env=clean_env(), cwd=self.tmp.name, timeout=300)
        self.assertEqual(r.returncode, want, r.stdout.decode('utf-8', errors='replace')[-400:])
        res = json.loads(r.stdout.decode('utf-8'))
        if want in CHECK_WIPE_RESULT:
            self.assertEqual(res['result'], CHECK_WIPE_RESULT[want])
            self.assertEqual(sorted(res['compilers']), sorted(COMPILERS))
            self.assertTrue(all(v in ('SURVIVED', 'ELIMINATED') for v in res['compilers'].values()), res)


def _cw_test(f, fn, want):
    return lambda self: self.run_case(f, fn, want)


for _i, (_f, _fn, _want) in enumerate(CHECK_WIPE_CASES, 1):
    _m = _cw_test(_f, _fn, _want)
    _m.__doc__ = f'check_wipe.py {_f} {_fn} -> exit {_want}'
    setattr(SkillCheckWipe, f'test_check_wipe_{_i:02d}_' + re.sub(r'\W+', '_', f'{_f}_{_fn}').lower(), _m)


if __name__ == '__main__':
    unittest.main()
