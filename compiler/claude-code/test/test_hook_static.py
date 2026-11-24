#!/usr/bin/env python3
"""Tests of the Claude Code hook and skill that need no compiler.

Every path tested here returns before a compiler would run, and the tests
prove that they do: the hook is run with VG_HOOK_CCS naming compilers that do
not exist and VG_WSL_DISTRO naming a distribution that does not exist, so any
attempt to compile -- directly on Linux, through WSL on Windows -- would turn
into exit 2. An exit 0 under those settings is an exit 0 that compiled nothing.

    python3 compiler/claude-code/test/test_hook_static.py

Run as a file: the directory name is not a Python package name. Runs on Linux
and on Windows. Nothing is written into the repository: no bytecode (the flag
below, and PYTHONDONTWRITEBYTECODE for the hook processes), and every input
this file makes is written to a temporary directory.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
# The hook reads its settings from the environment when it is imported; drop
# the caller's so that the constants below are the hook's defaults.
for _k in [k for k in os.environ if k.startswith(('VG_', 'WPIN_'))]:
    del os.environ[_k]
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..'))
HOOK_DIR = os.path.join(ROOT, 'hook')
HOOK = os.path.join(HOOK_DIR, 'vg_wipe_hook.py')
SKILL_DIR = os.path.join(ROOT, 'skill', 'secret-wipe-c')
CASES = os.path.join(HERE, 'cases')
sys.path.insert(0, HOOK_DIR)
import vg_wipe_hook  # noqa: E402
import wipe_core  # noqa: E402

ABSENT_CCS = 'vg-absent-cc-1,vg-absent-cc-2'
ABSENT_DISTRO = 'vg-absent-distro'
HOOK_PATH_IN_SETTINGS = '${CLAUDE_PROJECT_DIR}/.claude/hooks/vg_wipe/vg_wipe_hook.py'

# sha256 of every shipped file: the copy that was measured, and the copy here.
# README.md "Provenance" is this table in prose; a change to either file has to
# change both. Only wipe_core.py differs (three lines, see the README). The
# test cases are pinned too, so the cases the tests read are the measured ones.
PROVENANCE = {
    'hook/vg_wipe_hook.py': ('0485cdabb5eb8efcfbf64a82a204eef9229a8789b364242f3cf3884e1294d62e',) * 2,
    'hook/wipe_core.py': ('531183f9e57e5878e31ba4e349efff65e3851f76cbbc975cab1c042f06b3f84f',
                          '398cef6cf94bcc0f97b7eb81b270d6c4162cbcefd64edbbba9deebd13a2c9bd8'),
    'hook/check_wipe.py': ('c532a1bfd845bd881d156343286f1d6706466ef06bba9e5206f46e7dbcd20014',) * 2,
    'hook/settings.project.json': ('83febbcb9f4bfcb5013d149db60a153f2090b480f12b2e8a1ae883c2aab30c2d',) * 2,
    'hook/settings.project.linux.json': ('dde03558120bccd588d67726a1c2f8364884b86b07b0045d427d7cb2814e570b',) * 2,
    'skill/secret-wipe-c/SKILL.md': ('dc844ccdf3412472b38a7941b851d2c46ebbe68f65b1d1614518006f69af0563',) * 2,
    'skill/secret-wipe-c/scripts/check_wipe.py': ('c532a1bfd845bd881d156343286f1d6706466ef06bba9e5206f46e7dbcd20014',) * 2,
    # The inputs of the measured unit tests, byte for byte.
    'test/cases/broken.c': ('713ee8f88990df1f9a1e2fd599624c14d82dfe0d5ac4547cc4a7c1bbd38e1ac5',) * 2,
    'test/cases/deleted.c': ('abb1c2ad392f4ec4a784f8b030306e7ea5c82c7141d8eaf14541575ef5edefdc',) * 2,
    'test/cases/header.h': ('0a0a751b2080c44fd758b1f326bcf708d19cefe8ff91b5d93988130871e4f1a6',) * 2,
    'test/cases/helper.c': ('b2a4015267877fa4ed55e27a7ba4992d7aa3eda1431c967851cca554d075c639',) * 2,
    'test/cases/ifdef.c': ('0e6b41f1e33deea51df156709d29e0c4c6d2a339dc44e3512d68e54f2a4a56c8',) * 2,
    'test/cases/keyutil.h': ('0365a13af05428e01e46da2688315453c4431f7a0a96519b5c7225cc36572357',) * 2,
    'test/cases/notc.py': ('1bc86ad89f5b535754a080e7688ee61715f96f99785cd659a6f2213b8a26338f',) * 2,
    'test/cases/nowipe.c': ('20caa4cc4d0f77a4f8b54ed602c3b0ca435b2d550692391cfc909a3934dbe002',) * 2,
    'test/cases/partial.c': ('49f52584d128fcfb71bbedd2cbde375a73e98f53585e3c4b17f9c170612f518b',) * 2,
    'test/cases/safe.c': ('49a8fac82a7206fee69eebad39dada010fada06f19cddfdb9f1dd48e705aac87',) * 2,
    'test/cases/vfnptr.c': ('5e88ca5b0020e91806bcc88a657948ec7f3f7fa3e2713e66f5b602fd920ae289',) * 2,
    'test/cases/withheader.c': ('8e97e7d547520411d955563991ee56624a17888e5a5b44d0e8f1868beb00120d',) * 2,
}


def event(tool, path, cwd):
    """A PostToolUse input with the keys Claude Code sends (the session and
    tool-use ids are made up)."""
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
    return {'session_id': 'test-session', 'transcript_path': 'test-transcript.jsonl', 'cwd': cwd,
            'permission_mode': 'default', 'hook_event_name': 'PostToolUse', 'tool_name': tool,
            'tool_input': ti, 'tool_response': resp, 'tool_use_id': 'test-toolu-0001', 'duration_ms': 1}


def run_hook(stdin, workdir):
    """Run the hook as Claude Code does (stdin JSON, no shell) with compilers
    and a WSL distribution that do not exist. Returns (exit, stderr lines, stdout)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(('VG_', 'WPIN_'))}
    env.update(PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1', VG_HOOK_CCS=ABSENT_CCS, VG_WSL_DISTRO=ABSENT_DISTRO)
    data = stdin if isinstance(stdin, str) else json.dumps(stdin, ensure_ascii=False)
    r = subprocess.run([sys.executable, '-B', HOOK], input=data.encode('utf-8'), capture_output=True,
                       env=env, cwd=workdir, timeout=120)
    err = r.stderr.decode('utf-8', errors='replace').rstrip('\n')
    return r.returncode, (err.split('\n') if err else []), r.stdout.decode('utf-8', errors='replace')


HEAD = ('#include <string.h>\n#include <stddef.h>\n\n'
        'void read_key(unsigned char *out, size_t n);\n'
        'int use_key(const unsigned char *key, size_t n);\n\n')


def one_function(wipe, prelude=''):
    """The deleted.c shape with its wipe statement replaced: without a prelude
    the wipe is on line 12, as in deleted.c."""
    return (HEAD + prelude + '/* the wipe under test */\nint encrypt_once(void) {\n    unsigned char key[32];\n'
            '    read_key(key, sizeof(key));\n    int rc = use_key(key, sizeof(key));\n'
            '    ' + wipe + '\n    return rc;\n}\n')


# Wipes the hook does not recognise as wipes. Measured by hand with clang-18 and
# gcc-13 at -O2 (see README.md, "What it cannot see"); here only the hook's side
# is pinned: the scan finds nothing, so the hook exits 0 and says nothing.
UNSEEN = {
    "memset with '\\0'": one_function("memset(key, '\\0', sizeof(key));"),
    '__builtin_memset': one_function('__builtin_memset(key, 0, sizeof(key));'),
    'plain loop': one_function('for (size_t i = 0; i < sizeof(key); i++) key[i] = 0;'),
    'macro without a marker': one_function('WIPE(key);', '#define WIPE(p) memset((p), 0, sizeof(p))\n\n'),
    'typedef of a volatile function pointer': one_function(
        'memset_v(key, 0, sizeof(key));',
        'typedef void *(*memset_t)(void *, int, size_t);\nstatic volatile memset_t memset_v = memset;\n\n'),
}


class PathsThatCompileNothing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def assertSilentZero(self, rc, err, out):
        self.assertEqual((rc, err, out), (0, [], ''))

    def test_a_file_that_is_not_c(self):
        self.assertSilentZero(*run_hook(event('Write', os.path.join(CASES, 'notc.py'), CASES), self.tmp.name))

    def test_a_header_is_not_checked(self):
        self.assertSilentZero(*run_hook(event('Write', os.path.join(CASES, 'header.h'), CASES), self.tmp.name))

    def test_a_tool_other_than_write_or_edit(self):
        # deleted.c has a wipe the compilers delete: only the tool name stops the check.
        ev = dict(event('Write', os.path.join(CASES, 'deleted.c'), CASES), tool_name='Read')
        self.assertSilentZero(*run_hook(ev, self.tmp.name))

    def test_c_without_a_wipe_is_not_compiled(self):
        self.assertSilentZero(*run_hook(event('Write', os.path.join(CASES, 'nowipe.c'), CASES), self.tmp.name))

    def test_input_that_is_not_json(self):
        rc, err, out = run_hook('this is not json', self.tmp.name)
        self.assertEqual((rc, len(err), out), (2, 2, ''))
        self.assertIn('入力（JSON）を読めず', err[0])
        self.assertIn('コードの誤りではない', err[1])

    def test_a_missing_file_is_named_without_its_directory(self):
        # The cwd is another directory, so the hook may print the base name only.
        missing = os.path.join(self.tmp.name, 'sub', 'missing.c')
        rc, err, out = run_hook(event('Write', missing, os.path.join(self.tmp.name, 'elsewhere')), self.tmp.name)
        self.assertEqual((rc, len(err), out), (2, 2, ''))
        self.assertRegex(err[0], r'^VibeGuard: missing\.c が見つからず')
        self.assertNotIn(self.tmp.name, '\n'.join(err))
        self.assertIn('確かめられていない', err[1])

    def test_a_check_that_cannot_run_is_exit_2_not_a_code_error(self):
        # Linux: the named compilers are not installed. Windows: the WSL
        # distribution does not exist. Either way the hook must not exit 0.
        rc, err, out = run_hook(event('Write', os.path.join(CASES, 'deleted.c'), CASES), self.tmp.name)
        self.assertEqual((rc, len(err), out), (2, 2, ''))
        if os.name == 'nt':
            self.assertRegex(err[0], r'道具を実行できなかった|結果を返さなかった')
        else:
            self.assertRegex(err[0], r'環境が整っておらず.*NOT_INSTALLED')
        self.assertIn('コードの誤りではない', err[1])

    def test_the_positive_control_of_the_unseen_shapes_is_seen(self):
        # Same function, same line, a plain memset: the scan finds it, so the
        # UNSEEN cases below are blind spots of the scan, not of the template.
        found = wipe_core.scan(one_function('memset(key, 0, sizeof(key));'))
        self.assertEqual([(c['fn'], [w['line'] for w in c['wipes']]) for c in found], [('encrypt_once', [12])])
        p = os.path.join(self.tmp.name, 'control.c')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(one_function('memset(key, 0, sizeof(key));'))
        rc, err, _ = run_hook(event('Write', p, self.tmp.name), self.tmp.name)
        self.assertEqual(rc, 2, err)  # it tried to compile, and the compilers are absent

    def test_unseen_wipes_exit_0_without_compiling(self):
        for name, src in UNSEEN.items():
            with self.subTest(name):
                self.assertEqual(wipe_core.scan(src), [])
                p = os.path.join(self.tmp.name, re.sub(r'\W+', '_', name) + '.c')
                with open(p, 'w', encoding='utf-8') as f:
                    f.write(src)
                self.assertSilentZero(*run_hook(event('Write', p, self.tmp.name), self.tmp.name))


def strings_of(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from strings_of(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings_of(v)


def load_settings(name):
    with open(os.path.join(HOOK_DIR, name), encoding='utf-8') as f:
        return json.load(f)


class Settings(unittest.TestCase):
    NAMES = {'settings.project.json': 'python', 'settings.project.linux.json': 'python3'}

    def test_the_hook_entry(self):
        for name, interpreter in self.NAMES.items():
            with self.subTest(name):
                doc = load_settings(name)
                self.assertEqual(list(doc), ['hooks'])
                self.assertEqual(list(doc['hooks']), ['PostToolUse'])
                (entry,) = doc['hooks']['PostToolUse']
                self.assertEqual(entry['matcher'], 'Write|Edit')
                (h,) = entry['hooks']
                self.assertEqual(h['type'], 'command')
                self.assertEqual(h['command'], interpreter)
                self.assertEqual(h['args'], [HOOK_PATH_IN_SETTINGS])
                self.assertTrue(h['statusMessage'].startswith('VibeGuard: '))

    def test_no_absolute_path(self):
        absolute = re.compile(r'(^|[\s"\'])(/|[A-Za-z]:[\\/]|\\\\|~[\\/])')
        home = re.compile(r'[\\/](home|root|mnt|Users)[\\/]', re.I)
        for name in self.NAMES:
            with self.subTest(name):
                for s in strings_of(load_settings(name)):
                    self.assertIsNone(absolute.search(s), s)
                    self.assertIsNone(home.search(s), s)

    def test_the_two_files_differ_only_in_the_interpreter(self):
        a, b = (load_settings(n) for n in self.NAMES)
        a['hooks']['PostToolUse'][0]['hooks'][0].pop('command')
        b['hooks']['PostToolUse'][0]['hooks'][0].pop('command')
        self.assertEqual(a, b)

    def test_the_hook_times_out_before_claude_code_does(self):
        # The hook's own timeout (VG_HOOK_TIMEOUT, default 100 s) has to fire
        # first, so that a slow check ends in the hook's exit-2 message rather
        # than in Claude Code killing the process.
        self.assertEqual(vg_wipe_hook.TIMEOUT, 100)
        for name in self.NAMES:
            self.assertGreater(load_settings(name)['hooks']['PostToolUse'][0]['hooks'][0]['timeout'], vg_wipe_hook.TIMEOUT)


class SkillAndProvenance(unittest.TestCase):
    def test_the_hook_and_the_skill_carry_the_same_check_wipe(self):
        with open(os.path.join(HOOK_DIR, 'check_wipe.py'), 'rb') as f:
            a = f.read()
        with open(os.path.join(SKILL_DIR, 'scripts', 'check_wipe.py'), 'rb') as f:
            b = f.read()
        self.assertEqual(a, b)

    def test_skill_front_matter(self):
        with open(os.path.join(SKILL_DIR, 'SKILL.md'), encoding='utf-8') as f:
            text = f.read()
        m = re.match(r'---\n(.*?)\n---\n', text, re.S)
        self.assertIsNotNone(m)
        fields = dict(line.split(': ', 1) for line in m.group(1).split('\n'))
        self.assertEqual(sorted(fields), ['description', 'name'])
        self.assertEqual(fields['name'], 'secret-wipe-c')
        self.assertGreater(len(fields['description']), 0)
        self.assertIn('scripts/check_wipe.py', text)

    def test_cases_are_exactly_the_pinned_ones(self):
        # A case added or removed without its PROVENANCE row fails here.
        pinned = sorted(rel.split('/', 2)[2] for rel in PROVENANCE if rel.startswith('test/cases/'))
        self.assertEqual(sorted(os.listdir(CASES)), pinned)

    def test_digests(self):
        for rel, (measured, shipped) in PROVENANCE.items():
            with self.subTest(rel):
                with open(os.path.join(ROOT, *rel.split('/')), 'rb') as f:
                    self.assertEqual(hashlib.sha256(f.read()).hexdigest(), shipped)
                if rel != 'hook/wipe_core.py':
                    self.assertEqual(measured, shipped)


if __name__ == '__main__':
    unittest.main()
