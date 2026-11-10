#!/usr/bin/env python3
"""Unit tests for the pure parts of vgpin-cc: the response-file tokenizer, the
command-line classifier, the version reader, the pins reader, the record
reader, and the rule for withholding an output.

    python3 compiler/pin-wrapper/test/test_vgpin_parse.py

(run as a file, for the same reason as test_vgpin_cc.py). The wrapper is a
script without a .py suffix, so it is loaded by path.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from vgpin_fakes import EXAMPLE_PINS, VERSION_TEXT, WRAPPER, record, record_v2, record_v3  # noqa: E402


def load_wrapper():
    loader = SourceFileLoader('vgpin_cc', WRAPPER)
    spec = importlib.util.spec_from_loader('vgpin_cc', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


V = load_wrapper()


# compiler/schema/wipe-pin.md section 14.11, copied 2026-11-05 (constructed examples, not captured).
WIPEPIN_V3_EXAMPLE = r'''{"schemaVersion":"wipe-pin-v3","component":"WipePin","module":"session.c","toolchain":{"clang":"18.1.3","packages":[{"name":"llvm","version":"18.1.3"}],"digest":"a532c6b0418aba5c30e069c3b9b2b9657b3d8f256ec342d27b2fb9df625a35cd"},"optLevel":{"speedup":2,"size":0},"scope":"functions","requested":["close_session"],"resolution":[{"name":"close_session","resolution":"resolved","exact":true,"linkage":"external"}],"dryRun":false,"pinned":[{"function":"close_session","index":0,"lengthBytes":32,"destKind":"alloca","alreadyVolatile":false,"followedByUse":true,"line":41}],"pinnedCount":1,"wouldPinCount":1,"seen":{"zeroFillMemsetInScope":1,"zeroFillMemsetInModule":2},"unhandled":{"libcallMemset":0,"memsetChk":0,"nonZeroFill":1,"atomicMemset":0,"inlineWrapperMemset":0,"bzeroCall":0,"inlineWrapperBzero":0,"zeroGlobalCopy":0,"zeroGlobalCopyCall":0},"barrierCalls":{"enabled":true,"sites":[{"function":"close_session","callee":"memset.inline","lengthBytes":32,"line":57}],"barrierCount":1,"wouldBarrierCount":1},"zeroCopy":{"enabled":true,"sites":[{"function":"close_session","form":"call","callee":"memcpy.inline","source":"zero_block","destKind":"alloca","lengthBytes":64,"line":58}],"repairedCount":1,"wouldRepairCount":1},"bufferBarriers":{"enabled":false,"count":0,"sites":[]},"host":{"ident":"Ubuntu clang version 18.1.3","identMajor":18,"builtMajor":18,"checked":true,"intrinsicsCompared":null},"evidenceDigest":"4eca66759c0a3475a9aedb15f35bc9b8690310db743e85d23c9a6fccb542f9b3","context":{"timeSource":"SOURCE_DATE_EPOCH","sourceDateEpoch":1762300800,"generatedAt":1762300800}}'''
WIPEPINGCC_V3_DRY_EXAMPLE = r'''{"schemaVersion":"wipe-pin-v3","component":"WipePinGcc","module":"session.c","toolchain":{"gcc":"13.3.0","packages":[{"name":"gcc","version":"13.3.0"}],"digest":"59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0"},"optLevel":{"speedup":2,"size":0},"scope":"module","requested":[],"resolution":[],"dryRun":true,"pinned":[{"function":"close_session","index":0,"lengthBytes":32,"destKind":"alloca","alreadyVolatile":false,"followedByUse":false,"line":55}],"pinnedCount":0,"wouldPinCount":1,"seen":{"zeroFillMemsetInScope":1,"zeroFillMemsetInModule":1},"unhandled":{"libcallMemset":1,"memsetChk":0,"nonZeroFill":0,"atomicMemset":0,"inlineWrapperMemset":0,"bzeroCall":0,"inlineWrapperBzero":0,"zeroGlobalCopy":0,"zeroGlobalCopyCall":0},"barrierCalls":{"enabled":true,"sites":[{"function":"close_session","callee":"bzero","lengthBytes":16,"line":56}],"barrierCount":0,"wouldBarrierCount":1},"zeroCopy":{"enabled":true,"sites":[{"function":"close_session","form":"aggregate","callee":null,"source":"zero_block","destKind":"alloca","lengthBytes":64,"line":58}],"repairedCount":0,"wouldRepairCount":1},"bufferBarriers":{"enabled":false,"count":0,"sites":[]},"host":{"ident":"13.3.0","identMajor":13,"builtMajor":13,"checked":true,"intrinsicsCompared":null},"evidenceDigest":"3904af95abe913d30dc707fa10a9e7f51737f6d56bc95a21c15b2f4fe145c77e","context":{"timeSource":"SOURCE_DATE_EPOCH","sourceDateEpoch":1762300800,"generatedAt":1762300800}}'''


class Tokenizer(unittest.TestCase):
    def test_quotes_and_escapes(self):
        self.assertEqual(V.tokenize_response_file('-c  "a b.c"\t\'x y\' c\\ d\n-o"o"'),
                         ['-c', 'a b.c', 'x y', 'c d', '-oo'])

    def test_empty_quotes_make_an_empty_argument(self):
        self.assertEqual(V.tokenize_response_file('a "" b'), ['a', '', 'b'])

    def test_expansion_is_recursive_and_relative_to_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'sub'))
            with open(os.path.join(d, 'sub', 'inner.rsp'), 'w') as f:
                f.write('u.c')
            with open(os.path.join(d, 'outer.rsp'), 'w') as f:
                f.write('-c t.c @sub/inner.rsp')
            out, problems = V.expand_response_files(['-O2', '@outer.rsp'], d)
            self.assertEqual((out, problems), (['-O2', '-c', 't.c', 'u.c'], []))

    def test_a_cycle_and_a_missing_file_are_problems(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'loop.rsp'), 'w') as f:
                f.write('@loop.rsp')
            _, problems = V.expand_response_files(['@loop.rsp', '@nope.rsp'], d)
            self.assertEqual(len(problems), 2)
            self.assertIn('includes itself', problems[0])
            self.assertIn('cannot be read', problems[1])

    def test_a_lone_at_sign_is_an_argument(self):
        self.assertEqual(V.expand_response_files(['@'], '.'), (['@'], []))


class Classify(unittest.TestCase):
    def c(self, *args):
        return V.classify(list(args))

    def test_values_of_options_are_not_inputs(self):
        info = self.c('-include', 'x.c', '-MF', 'y.c', '-o', 'z.o', '-c', 't.c', '-Xclang', 'w.c', '-mllvm', 'v.c')
        self.assertEqual(info['sources'], ['t.c'])
        self.assertEqual(info['output'], 'z.o')

    def test_joined_output_forms(self):
        self.assertEqual(self.c('-c', 't.c', '-ox.o')['output'], 'x.o')
        self.assertEqual(self.c('-c', 't.c', '--output=y.o')['output'], 'y.o')
        self.assertEqual(self.c('-c', 't.c', '--output', 'w.o')['output'], 'w.o')
        self.assertIsNone(self.c('-c', 't.c', '-objcmt-migrate-literals')['output'])

    def test_language_applies_to_later_inputs(self):
        info = self.c('a.txt', '-x', 'c', 'b.txt', '-x', 'none', 'c.txt', '-xassembler-with-cpp', 'd.txt')
        self.assertEqual(info['others'], ['a.txt', 'c.txt'])
        self.assertEqual(info['sources'], ['b.txt'])
        self.assertEqual(info['asm'], ['d.txt'])

    def test_kinds_by_extension(self):
        info = self.c('t.c', 'u.cpp', 'a.S', 'b.s', 'h.h', 'x.o', 'libz.a', 'y.ll')
        self.assertEqual(info['sources'], ['t.c', 'u.cpp', 'y.ll'])
        self.assertEqual(info['asm'], ['a.S', 'b.s'])
        self.assertEqual(info['headers'], ['h.h'])
        self.assertEqual(info['others'], ['x.o', 'libz.a'])

    def test_stop_stage_earliest_wins(self):
        self.assertEqual(self.c('-c', '-S', 't.c')['stop'], 'asm')
        self.assertEqual(self.c('-S', '-c', 't.c')['stop'], 'asm')
        self.assertEqual(self.c('-c', 't.c')['stop'], 'obj')
        self.assertEqual(self.c('t.c')['stop'], 'link')
        self.assertEqual(self.c('-c', '-E', 't.c')['stop'], 'pre')

    def test_lto_last_word_wins(self):
        self.assertTrue(self.c('-flto=thin', 't.c')['lto'])
        self.assertFalse(self.c('-flto', '-fno-lto', 't.c')['lto'])
        self.assertTrue(self.c('-fno-lto', '-flto', 't.c')['lto'])
        self.assertFalse(self.c('-flto-partition=one', 't.c')['lto'])

    def test_default_outputs(self):
        self.assertEqual(V.default_output('dir/t.c', 'obj', False), 't.o')
        self.assertEqual(V.default_output('t.c', 'obj', True), 't.bc')
        self.assertEqual(V.default_output('t.c', 'asm', False), 't.s')
        self.assertEqual(V.default_output('t.c', 'asm', True), 't.ll')
        self.assertEqual(V.default_output('-', 'obj', False), '-.o')
        self.assertEqual(V.default_output('t.c', 'link', False), 'a.out')


class Decide(unittest.TestCase):
    def d(self, *args):
        return V.decide(V.classify(list(args)))

    def refused(self, *args):
        with self.assertRaises(V.Refusal) as cm:
            self.d(*args)
        return cm.exception

    def test_pass_and_compile(self):
        self.assertEqual(self.d('--version', '-c', 't.c')[0], 'pass')
        self.assertEqual(self.d('-E', 't.c')[0], 'pass')
        self.assertEqual(self.d('t.o', '-o', 'app')[0], 'pass')
        self.assertEqual(self.d('-c', 'a.S')[0], 'pass')
        self.assertEqual(self.d('-v')[0], 'pass')
        self.assertEqual(self.d()[0], 'pass')
        self.assertEqual(self.d('-v', '-c', 't.c'), ('compile', None))
        self.assertEqual(self.d('-c', '-x', 'c', '-'), ('compile', None))
        self.assertEqual(self.d('-c', 't.c', 'x.o'), ('compile', None))

    def test_refusals(self):
        self.assertEqual(self.refused('-c', 't.c', 'u.c').code, 5)
        self.assertEqual(self.refused('-c', 't.c', 'a.S').code, 5)
        self.assertEqual(self.refused('-c', 't.c', 'h.h').code, 5)
        self.assertEqual(self.refused('-S', 't.c', '-o', '-').code, 5)


class Identify(unittest.TestCase):
    def test_real_first_lines(self):
        self.assertEqual(V.identify(VERSION_TEXT['clang-18']), ('clang', 18))
        self.assertEqual(V.identify(VERSION_TEXT['clang-19']), ('clang', 19))
        self.assertEqual(V.identify(VERSION_TEXT['gcc-13']), ('gcc', 13))
        self.assertEqual(V.identify(VERSION_TEXT['gcc-12']), ('gcc', 12))
        self.assertEqual(V.identify(VERSION_TEXT['cc']), ('gcc', 13))
        self.assertEqual(V.identify('gcc (GCC) 14.2.1 20240910\n'), ('gcc', 14))
        self.assertEqual(V.identify('clang version 20.1.8\nTarget: x\n'), ('clang', 20))

    def test_unknown(self):
        self.assertIsNone(V.identify(VERSION_TEXT['weird-cc']))
        self.assertIsNone(V.identify(''))


class Pins(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='vgpin-pins-')
        self.path = os.path.join(self.dir, 'pins.json')
        self.good = {'family': 'clang', 'compilerMajor': 18, 'plugin': 'lib/libWipePin.so', 'sha256': 'a' * 64}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, doc):
        with open(self.path, 'w') as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))

    def load(self, doc):
        self.write(doc)
        return V.load_pins(self.path)

    def refused(self, doc, text):
        with self.assertRaises(V.Refusal) as cm:
            self.load(doc)
        self.assertEqual(cm.exception.code, 4)
        self.assertIn(text, cm.exception.message)

    def test_good_and_defaults(self):
        pins, ignore = self.load({'schemaVersion': 'vgpin-pins-v1', 'pins': [self.good], 'comment': 'x'})
        self.assertEqual(ignore, ['memsetChk', 'nonZeroFill'])
        self.assertEqual(pins[0]['plugin'], os.path.join(self.dir, 'lib', 'libWipePin.so'))
        self.assertEqual(pins[0]['env'], {})

    def test_each_way_it_is_refused(self):
        base = {'schemaVersion': 'vgpin-pins-v1', 'pins': [self.good]}
        self.refused('{', 'is not JSON')
        self.refused('[]', 'not a JSON object')
        self.refused(dict(base, extra=1), 'unknown key')
        self.refused(dict(base, schemaVersion='vgpin-pins-v0'), 'schemaVersion')
        self.refused(dict(base, pins=[]), 'non-empty list')
        self.refused(dict(base, pins=[dict(self.good, famly='clang')]), 'unknown key')
        self.refused(dict(base, pins=[dict(self.good, family='icc')]), 'family')
        self.refused(dict(base, pins=[dict(self.good, compilerMajor='18')]), 'compilerMajor')
        self.refused(dict(base, pins=[dict(self.good, compilerMajor=True)]), 'compilerMajor')
        self.refused(dict(base, pins=[dict(self.good, sha256='A' * 64)]), 'sha256')
        self.refused(dict(base, pins=[dict(self.good, plugin='')]), 'plugin')
        self.refused(dict(base, pins=[dict(self.good, env={'WPIN_OUT': 'x'})]), 'not a plugin switch')
        self.refused(dict(base, pins=[dict(self.good, env={'WPIN_SCOPE': 'module'})]), 'not a plugin switch')
        self.refused(dict(base, pins=[dict(self.good, env={'PATH': '/x'})]), 'not a plugin switch')
        self.refused(dict(base, pins=[dict(self.good, env={'WPIN_BARRIER_CALLS': 'on'})]), '"0" or "1"')
        self.refused(dict(base, pins=[self.good, dict(self.good)]), 'a second pin')
        self.refused(dict(base, unhandledIgnore='memsetChk'), 'unhandledIgnore')
        self.refused(dict(base, unhandledIgnore=['a', 'a']), 'unhandledIgnore')

    def test_the_example_file_parses_as_json_and_is_refused_for_its_placeholders(self):
        with open(EXAMPLE_PINS, encoding='utf-8') as f:
            doc = json.load(f)
        self.assertEqual(doc['schemaVersion'], 'vgpin-pins-v1')
        for p in doc['pins']:
            self.assertFalse(p['plugin'].startswith('/'), 'the example must not carry an absolute path')
        with self.assertRaises(V.Refusal) as cm:
            V.load_pins(EXAMPLE_PINS)
        self.assertIn('sha256', cm.exception.message)


class Record(unittest.TestCase):
    IGN = list(V.DEFAULT_UNHANDLED_IGNORE)

    def check(self, rec, fam='clang', major=18, env=None, require=False):
        return V.check_record(rec, fam, major, env or {}, self.IGN, require)[0]

    def test_good_v3_and_v2_refused(self):
        self.assertEqual(self.check(record('clang')), [])
        self.assertEqual(self.check(record('gcc'), 'gcc', 13), [])
        self.assertEqual(self.check(record_v3('clang')), [])
        self.assertEqual(self.check(record_v3('gcc'), 'gcc', 13), [])
        self.assertEqual(V.RECORD_VERSIONS, ('wipe-pin-v3',))
        for fam, major in (('clang', 18), ('gcc', 13)):
            probs = self.check(record_v2(fam), fam, major)
            self.assertEqual(len(probs), 1, probs)
            self.assertIn("'wipe-pin-v2', not one of wipe-pin-v3", probs[0])

    def test_a_v3_record_needs_its_host_block(self):
        rec = record('clang')
        del rec['host']
        self.assertIn('the record has no host object', self.check(rec))
        self.assertIn('the record field host is not an object', self.check(record('clang', host=[])))

    def test_not_an_object_or_wrong_version(self):
        self.assertTrue(self.check([]))
        self.assertTrue(self.check(record('clang', schemaVersion='wipe-pin-v4')))
        self.assertTrue(self.check(record('clang', schemaVersion=None)))

    def test_toolchain(self):
        self.assertIn('built against clang 18.1.3', self.check(record('clang'), major=19)[0])
        self.assertTrue(self.check(record('clang', toolchain={'packages': []})))
        self.assertTrue(self.check(record('clang', toolchain='18.1.3')))

    def test_counts_must_be_counts(self):
        self.assertTrue(self.check(record('clang', pinnedCount=True)))
        self.assertTrue(self.check(record('clang', pinnedCount=-1)))
        self.assertTrue(self.check(record('clang', wouldPinCount=None)))
        self.assertTrue(self.check(record_v3('clang', zeroCopy={'repairedCount': 'x'})))
        self.assertTrue(self.check(record_v3('clang', zeroCopy=[])))

    def test_zero_copy_left_undone(self):
        probs = self.check(record_v3('clang', zeroCopy={'sites': [], 'repairedCount': 0, 'wouldRepairCount': 1}))
        self.assertIn('zeroCopy were not repaired', probs[0])

    def test_switch_enabled_false(self):
        rec = record_v3('clang')
        probs = self.check(rec, env={'WPIN_BUFFER_BARRIER': '1'})
        self.assertIn('bufferBarriers.enabled false', probs[0])
        rec['bufferBarriers'] = {'enabled': True, 'count': 2, 'sites': []}
        self.assertEqual(self.check(rec, env={'WPIN_BUFFER_BARRIER': '1'}), [])

    def test_the_v3_examples_of_the_schema(self):
        # The two constructed examples of compiler/schema/wipe-pin.md 14.11,
        # copied on 2026-11-05. The WipePin one is in functions scope there;
        # the wrapper always compiles in module scope, so scope is the one
        # field changed here.
        clang = json.loads(WIPEPIN_V3_EXAMPLE)
        clang.update(scope='module', requested=[], resolution=[])
        probs, summary = V.check_record(clang, 'clang', 18, {'WPIN_BARRIER_CALLS': '1', 'WPIN_ZERO_COPY': '1'},
                                        self.IGN, True)
        self.assertEqual(probs, [])
        self.assertEqual((summary['pinnedCount'], summary['repaired'], summary['followedByUse']), (1, 3, 1))
        gcc = json.loads(WIPEPINGCC_V3_DRY_EXAMPLE)
        probs = V.check_record(gcc, 'gcc', 13, {'WPIN_BARRIER_CALLS': '1', 'WPIN_ZERO_COPY': '1'}, self.IGN, False)[0]
        self.assertTrue(any('dryRun True' in p for p in probs), probs)
        self.assertTrue(any('libcallMemset=1' in p for p in probs), probs)
        self.assertTrue(any('were not pinned' in p for p in probs), probs)

    def test_the_summary_counts_repairs_and_initialisers(self):
        rec = record_v3('clang', barrierCalls={'sites': [], 'barrierCount': 2, 'wouldBarrierCount': 2})
        rec['pinned'][0]['followedByUse'] = True
        probs, summary = V.check_record(rec, 'clang', 18, {}, self.IGN, False)
        self.assertEqual(probs, [])
        self.assertEqual((summary['repaired'], summary['followedByUse']), (3, 1))


@unittest.skipUnless(os.name == 'posix', 'FIFOs and symlinks')
class Withhold(unittest.TestCase):
    def test_only_regular_files_and_links_are_moved(self):
        with tempfile.TemporaryDirectory() as d:
            fifo = os.path.join(d, 'out.fifo')
            os.mkfifo(fifo)
            V.withhold(fifo)
            self.assertTrue(os.path.exists(fifo))
            self.assertFalse(os.path.exists(fifo + '.vgpin-rejected'))
            regular = os.path.join(d, 't.o')
            with open(regular, 'w') as f:
                f.write('x')
            V.withhold(regular)
            self.assertFalse(os.path.exists(regular))
            self.assertTrue(os.path.isfile(regular + '.vgpin-rejected'))
            V.withhold(os.path.join(d, 'absent.o'))  # says so, raises nothing


if __name__ == '__main__':
    unittest.main()
