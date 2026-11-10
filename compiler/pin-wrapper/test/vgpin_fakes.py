"""Shared fakes for the vgpin-cc tests: a fake compiler, fake plugins, records
and a pins file, all written into a temporary directory at test time. Nothing
here runs a real compiler or loads a real plugin.

The fake compiler is a Python script named like the compiler it stands for
(clang-18, gcc-13, ...). It answers --version with that compiler's real first
lines, logs every call (argv and the WPIN_* variables it was given), and when a
plugin flag names one of the fake plugins it does what the spec in that file
says: remove the file at WPIN_OUT when it "loads" (both real plugins do), then
refuse, or write the given record. Then it writes the output file the way the
real drivers name it. A source containing `#error` fails the compile.
"""

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.normpath(os.path.join(HERE, '..', 'vgpin-cc'))
EXAMPLE_PINS = os.path.normpath(os.path.join(HERE, '..', 'pins.example.json'))

VERSION_TEXT = {
    'clang-17': 'Ubuntu clang version 17.0.6 (9ubuntu1)\nTarget: x86_64-pc-linux-gnu\nThread model: posix\n',
    'clang-18': 'Ubuntu clang version 18.1.3 (1ubuntu1)\nTarget: x86_64-pc-linux-gnu\nThread model: posix\n',
    'clang-19': 'Ubuntu clang version 19.1.1 (1ubuntu1~24.04.2)\nTarget: x86_64-pc-linux-gnu\nThread model: posix\n',
    'gcc-12': 'gcc-12 (Ubuntu 12.3.0-17ubuntu1) 12.3.0\nCopyright (C) 2022 Free Software Foundation, Inc.\n',
    'gcc-13': 'gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\nCopyright (C) 2023 Free Software Foundation, Inc.\n',
    'cc': 'cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\nCopyright (C) 2023 Free Software Foundation, Inc.\n',
    'weird-cc': 'Some Compiler 1.0\n',
}

FAKE_CC = r'''
import json, os, signal, sys
VERSION = __VERSION__
args = sys.argv[1:]
log = os.environ.get('FAKECC_LOG')
if log:
    with open(log, 'a') as f:
        f.write(json.dumps({'argv0': sys.argv[0], 'args': args,
                            'wpin': {k: v for k, v in os.environ.items() if k.startswith('WPIN_')}}) + '\n')
if '--version' in args:
    sys.stdout.write(VERSION)
    sys.exit(0)
VALUE = {'-o', '-x', '-MF', '-MT', '-MQ', '-D', '-U', '-I', '-include', '-Xclang', '-mllvm'}
plugin = out = None
stop = 'link'
lang = None
srcs = []
i = 0
while i < len(args):
    a = args[i]
    if a in VALUE:
        if a == '-o':
            out = args[i + 1]
        if a == '-x':
            lang = args[i + 1]
        i += 2
        continue
    if a.startswith(('-fpass-plugin=', '-fplugin=')):
        plugin = a.split('=', 1)[1]
    elif a.startswith('-o') and len(a) > 2:
        out = a[2:]
    elif a == '-c' and stop == 'link':
        stop = 'obj'
    elif a in ('-S', '-E'):
        stop = 'asm'
    elif a.startswith('@'):
        pass
    elif a == '-' or (not a.startswith('-') and (lang or a.endswith(('.c', '.S')))):
        srcs.append(a)
    i += 1
for s in srcs:
    text = sys.stdin.read() if s == '-' else open(s).read()
    if '#error' in text:
        sys.stderr.write(s + ': error: #error\n')
        sys.exit(1)
    if '#signal' in text:
        os.kill(os.getpid(), signal.SIGTERM)
wpin_out = os.environ.get('WPIN_OUT')
if plugin:
    with open(plugin) as f:
        spec = json.load(f)
    name = spec.get('component', 'WipePin')
    if wpin_out and os.path.lexists(wpin_out):
        os.remove(wpin_out)
    if spec.get('stderr'):
        sys.stderr.write(spec['stderr'] + '\n')
    if not wpin_out or os.environ.get('WPIN_SCOPE') != 'module':
        sys.stderr.write(name + ': refusing to install: no WPIN_OUT or no target\n')
    elif spec.get('refuse'):
        sys.stderr.write(name + ': refusing to install: ' + spec['refuse'] + '\n')
    elif spec.get('raw') is not None:
        with open(wpin_out, 'w') as f:
            f.write(spec['raw'])
    elif spec.get('record') is not None:
        with open(wpin_out, 'w') as f:
            f.write(json.dumps(spec['record']) + '\n')
if out is None:
    stem = '-' if srcs and srcs[0] == '-' else (os.path.splitext(os.path.basename(srcs[0]))[0] if srcs else 'a')
    out = {'obj': stem + '.o', 'asm': stem + '.s'}.get(stop, 'a.out')
if out == '-':
    sys.stdout.write('FAKE-OUTPUT\n')
elif stop != 'link' or srcs or any(a.endswith('.o') for a in args):
    with open(out, 'w') as f:
        f.write('FAKE-OUTPUT plugin=%s\n' % bool(plugin))
sys.exit(int(os.environ.get('FAKECC_RC', '0')))
'''


def record_v2(family='clang', version=None, **over):
    """A wipe-pin-v2 record of `family` in module scope, with `over` merged in
    (a dict value replaces). The wrapper refuses this version; it is kept only to
    show that refusal."""
    clang = family == 'clang'
    version = version or ('18.1.3' if clang else '13.3.0')
    rec = {
        'schemaVersion': 'wipe-pin-v2', 'component': 'WipePin' if clang else 'WipePinGcc', 'module': 't.c',
        'toolchain': {family: version, 'packages': [{'name': 'llvm' if clang else 'gcc', 'version': version}],
                      'digest': '0' * 64},
        'optLevel': {'speedup': 2, 'size': 0}, 'scope': 'module', 'requested': [], 'resolution': [],
        'dryRun': False,
        'pinned': [{'function': 'f', 'index': 0, 'lengthBytes': 32, 'destKind': 'alloca',
                    'alreadyVolatile': False, 'followedByUse': False, 'line': None}],
        'pinnedCount': 1, 'wouldPinCount': 1,
        'seen': {'zeroFillMemsetInScope': 1, 'zeroFillMemsetInModule': 1},
        'unhandled': {'libcallMemset': 0, 'memsetChk': 0, 'nonZeroFill': 0, 'atomicMemset': 0,
                      'inlineWrapperMemset': 0},
        'evidenceDigest': '0' * 64,
        'context': {'generatedAt': 0, 'timeSource': 'SOURCE_DATE_EPOCH', 'sourceDateEpoch': 0},
    }
    for k, v in over.items():
        rec[k] = copy.deepcopy(v)
    return rec


def record(family='clang', version=None, **over):
    """A record shaped the way the plugin of `family` writes one in module scope:
    wipe-pin-v3 (compiler/schema/wipe-pin.md section 14) with every switch off --
    nine unhandled counters, and the blocks barrierCalls, zeroCopy,
    bufferBarriers and host on every record, host naming the major of
    `version` -- with `over` merged in (a dict value replaces)."""
    clang = family == 'clang'
    version = version or ('18.1.3' if clang else '13.3.0')
    major = int(version.split('.')[0])
    base = record_v2(family, version)
    base['schemaVersion'] = 'wipe-pin-v3'
    base['unhandled'] = dict(base['unhandled'], bzeroCall=0, inlineWrapperBzero=0, zeroGlobalCopy=0,
                             zeroGlobalCopyCall=0)
    base['barrierCalls'] = {'enabled': False, 'sites': [], 'barrierCount': 0, 'wouldBarrierCount': 0}
    base['zeroCopy'] = {'enabled': False, 'sites': [], 'repairedCount': 0, 'wouldRepairCount': 0}
    base['bufferBarriers'] = {'enabled': False, 'count': 0, 'sites': []}
    base['host'] = {'ident': f'Ubuntu clang version {version}' if clang else version,
                    'identMajor': major, 'builtMajor': major, 'checked': True, 'intrinsicsCompared': None}
    for k, v in over.items():
        base[k] = copy.deepcopy(v)
    return base


# The name the v3 tests were written with; the same builder.
record_v3 = record


def sha256_file(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


class Lab:
    """One temporary directory with bin/, plugins/ and a working directory."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix='vgpin-test-')
        self.bin = os.path.join(self.root, 'bin')
        self.plugins = os.path.join(self.root, 'plugins')
        self.work = os.path.join(self.root, 'work')
        for d in (self.bin, self.plugins, self.work):
            os.makedirs(d)
        self.log = os.path.join(self.root, 'cc.log')
        self.pins_path = os.path.join(self.root, 'pins.json')

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def fake(self, name, version_text=None):
        path = os.path.join(self.bin, name)
        text = version_text if version_text is not None else VERSION_TEXT[name]
        with open(path, 'w', encoding='utf-8') as f:
            f.write('#!' + sys.executable + '\n' + FAKE_CC.replace('__VERSION__', repr(text)))
        os.chmod(path, 0o755)
        return path

    def plugin(self, name, record=None, refuse=None, raw=None, component=None):
        spec = {'record': record, 'refuse': refuse, 'raw': raw}
        if component:
            spec['component'] = component
        elif record and isinstance(record, dict) and 'component' in record:
            spec['component'] = record['component']
        path = os.path.join(self.plugins, name)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(spec, f)
        return path

    def pins(self, entries, **top):
        doc = {'schemaVersion': 'vgpin-pins-v1', 'pins': entries}
        doc.update(top)
        with open(self.pins_path, 'w', encoding='utf-8') as f:
            json.dump(doc, f)
        return self.pins_path

    def pin(self, family, major, plugin_path, env=None, **extra):
        p = {'family': family, 'compilerMajor': major, 'plugin': plugin_path, 'sha256': sha256_file(plugin_path)}
        if env is not None:
            p['env'] = env
        p.update(extra)
        return p

    def write(self, name, text):
        path = os.path.join(self.work, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        return path

    def env(self, cc='clang-18', extra=None, drop=()):
        e = {k: v for k, v in os.environ.items()
             if not k.startswith(('WPIN_', 'VG_PIN_', 'VGPIN_', 'FAKECC_'))}
        e['PATH'] = self.bin + os.pathsep + e.get('PATH', '')
        e['FAKECC_LOG'] = self.log
        e['VGPIN_PINS'] = self.pins_path
        if cc:
            e['VG_PIN_CC'] = cc
        e.update(extra or {})
        for k in drop:
            e.pop(k, None)
        return e

    def run(self, args, cc='clang-18', extra=None, drop=(), argv0=None, stdin=None):
        cmd = [argv0] if argv0 else [sys.executable, WRAPPER]
        return subprocess.run(cmd + list(args), cwd=self.work, env=self.env(cc, extra, drop),
                              input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              timeout=60)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log, encoding='utf-8') as f:
            return [json.loads(line) for line in f if line.strip()]

    def compiles(self):
        """Calls other than --version: the ones that would have compiled."""
        return [c for c in self.calls() if '--version' not in c['args']]

    def exists(self, name):
        return os.path.lexists(os.path.join(self.work, name))

    def install_wrapper_copy(self, link_name):
        """An executable copy of the wrapper in bin/, plus a symlink to it under
        `link_name`, for the argv[0] naming rule. (The tracked file's mode is
        not relied on: a checkout may not keep the executable bit.)"""
        copy_path = os.path.join(self.bin, 'vgpin-cc')
        shutil.copyfile(WRAPPER, copy_path)
        os.chmod(copy_path, os.stat(copy_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        link = os.path.join(self.bin, link_name)
        os.symlink('vgpin-cc', link)
        return link
