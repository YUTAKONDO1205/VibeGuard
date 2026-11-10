#!/usr/bin/env python3
"""End-to-end tests for vgpin-cc against a fake compiler and fake plugins.

    python3 compiler/pin-wrapper/test/test_vgpin_cc.py

(run as a file: the directory name has a hyphen, so it is not importable as a
package, and `python3 -m unittest` cannot address it by module name).

No real compiler and no real plugin is involved: vgpin_fakes.py writes a fake
`clang-18`/`gcc-13`/... into a temporary directory, and a "plugin" is a JSON
file telling the fake compiler what record to write. What these tests show is
the wrapper's own logic -- what it passes, what it refuses before running the
compiler, and what it does with each kind of record. Whether a real plugin
keeps a real wipe is measured separately (README "Measured").

POSIX only (symlinks, executable scripts, os.execve); CI runs it on Linux.
"""

import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from vgpin_fakes import EXAMPLE_PINS, WRAPPER, Lab, record, record_v2, record_v3, sha256_file  # noqa: E402

SRC = '#include <string.h>\nint f(void) { unsigned char k[32]; memset(k, 0, sizeof k); return 0; }\n'
POSIX = os.name == 'posix'


def stderr_lines(r):
    return [line for line in r.stderr.splitlines() if line.startswith('vgpin:')]


@unittest.skipUnless(POSIX, 'the wrapper and its fakes are POSIX programs')
class Base(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()
        self.addCleanup(self.lab.close)
        for name in ('clang-17', 'clang-18', 'clang-19', 'gcc-12', 'gcc-13', 'weird-cc'):
            self.lab.fake(name)
        self.lab.write('t.c', SRC)
        self.lab.write('u.c', SRC.replace('int f', 'int g'))
        self.lab.write('bad.c', '#error not compilable\n')
        self.clang_plugin = self.lab.plugin('libWipePin.so', record('clang'))
        self.gcc_plugin = self.lab.plugin('libWipePinGcc.so', record('gcc'))
        self.lab.pins([self.lab.pin('clang', 18, self.clang_plugin), self.lab.pin('gcc', 13, self.gcc_plugin)])

    def set_plugin(self, family, rec=None, **kw):
        """Replace a family's plugin behaviour and re-pin its sha256."""
        name = 'libWipePin.so' if family == 'clang' else 'libWipePinGcc.so'
        path = self.lab.plugin(name, rec, **kw)
        entries = [self.lab.pin('clang', 18, self.clang_plugin if family != 'clang' else path),
                   self.lab.pin('gcc', 13, self.gcc_plugin if family != 'gcc' else path)]
        self.lab.pins(entries)
        return path


class TheCompileItRuns(Base):
    def test_one_source_gets_the_pinned_plugin_and_module_scope(self):
        r = self.lab.run(['-O2', '-S', 't.c', '-o', 't.s'])
        self.assertEqual(r.returncode, 0, r.stderr)
        compiles = self.lab.compiles()
        self.assertEqual(len(compiles), 1)
        c = compiles[0]
        self.assertEqual(c['args'][0], '-fpass-plugin=' + self.clang_plugin)
        self.assertEqual(c['args'][1:], ['-O2', '-S', 't.c', '-o', 't.s'])
        self.assertEqual(c['wpin']['WPIN_SCOPE'], 'module')
        self.assertTrue(c['wpin']['WPIN_OUT'].endswith('wipe-pin.json'))
        self.assertEqual(set(c['wpin']), {'WPIN_OUT', 'WPIN_SCOPE'})
        self.assertTrue(self.lab.exists('t.s'))

    def test_object_output(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.lab.exists('t.o'))

    def test_gcc_gets_fplugin_and_its_own_pin(self):
        r = self.lab.run(['-O2', '-S', 't.c', '-o', 'g.s'], cc='gcc-13')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lab.compiles()[0]['args'][0], '-fplugin=' + self.gcc_plugin)

    def test_callers_wpin_variables_never_reach_the_compiler(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'],
                         extra={'WPIN_DRY_RUN': '1', 'WPIN_TARGET_FNS': 'nothing', 'WPIN_OUT': '/tmp/elsewhere'})
        self.assertEqual(r.returncode, 0, r.stderr)
        wpin = self.lab.compiles()[0]['wpin']
        self.assertEqual(set(wpin), {'WPIN_OUT', 'WPIN_SCOPE'})
        self.assertNotEqual(wpin['WPIN_OUT'], '/tmp/elsewhere')

    def test_a_pin_switch_reaches_the_compiler(self):
        rec = record('clang', barrierCalls={'sites': [], 'barrierCount': 1, 'wouldBarrierCount': 1})
        path = self.lab.plugin('libWipePinB.so', rec)
        self.lab.pins([self.lab.pin('clang', 18, path, env={'WPIN_BARRIER_CALLS': '1'})])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lab.compiles()[0]['wpin']['WPIN_BARRIER_CALLS'], '1')

    def test_compile_error_returns_the_compilers_code_and_reads_no_record(self):
        r = self.lab.run(['-O2', '-c', 'bad.c', '-o', 'bad.o'])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(stderr_lines(r), [])

    def test_a_compiler_killed_by_a_signal_is_128_plus_the_signal(self):
        self.lab.write('sig.c', '#signal\n')
        r = self.lab.run(['-O2', '-c', 'sig.c', '-o', 'sig.o'])
        self.assertEqual(r.returncode, 128 + 15)

    def test_the_record_is_copied_when_asked(self):
        rd = os.path.join(self.lab.root, 'records')
        r = self.lab.run(['-O2', '-S', 't.c', '-o', 'x.s'], extra={'VG_PIN_RECORD_DIR': rd})
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(rd, 'x.s.wipe-pin.json'), encoding='utf-8') as f:
            self.assertEqual(json.load(f)['component'], 'WipePin')

    def test_verbose_says_what_it_read(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_VERBOSE': '1'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any('pinned 1' in line for line in stderr_lines(r)), r.stderr)

    def test_relative_plugin_path_is_read_against_the_pins_file(self):
        rel = os.path.relpath(self.clang_plugin, os.path.dirname(self.lab.pins_path))
        self.lab.pins([{'family': 'clang', 'compilerMajor': 18, 'plugin': rel,
                        'sha256': sha256_file(self.clang_plugin)}])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lab.compiles()[0]['args'][0], '-fpass-plugin=' + self.clang_plugin)

    def test_argv0_names_the_compiler(self):
        link = self.lab.install_wrapper_copy('vgpin-clang-18')
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc=None, argv0=link)
        self.assertEqual(r.returncode, 0, r.stderr)
        # The kernel hands a #! script its path, not argv[0], so compare names.
        self.assertEqual(os.path.basename(self.lab.compiles()[0]['argv0']), 'clang-18')


class TheVersionHandshake(Base):
    def test_a_newer_clang_than_the_pin_is_refused_before_compiling(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='clang-19')
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn('major version 19', r.stderr)
        self.assertEqual(self.lab.compiles(), [])
        self.assertFalse(self.lab.exists('t.o'))

    def test_an_older_clang_than_the_pin_is_refused_before_compiling(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='clang-17')
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.lab.compiles(), [])

    def test_an_older_gcc_than_the_pin_is_refused_before_compiling(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='gcc-12')
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.lab.compiles(), [])

    def test_the_right_pin_is_chosen_when_several_majors_are_pinned(self):
        p19 = self.lab.plugin('libWipePin19.so', record('clang', version='19.1.1'))
        self.lab.pins([self.lab.pin('clang', 18, self.clang_plugin), self.lab.pin('clang', 19, p19)])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='clang-19')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lab.compiles()[0]['args'][0], '-fpass-plugin=' + p19)

    def test_a_compiler_whose_version_cannot_be_read_is_refused(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='weird-cc')
        self.assertEqual(r.returncode, 4)
        self.assertIn('cannot read the family and major version', r.stderr)
        self.assertEqual(self.lab.compiles(), [])

    def test_no_pin_for_the_family_is_refused(self):
        self.lab.pins([self.lab.pin('clang', 18, self.clang_plugin)])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='gcc-13')
        self.assertEqual(r.returncode, 4)
        self.assertIn('no gcc pin', r.stderr)

    def test_a_pin_that_misdeclares_the_major_is_caught_by_the_record(self):
        # The pins file claims a clang-18 plugin is for clang 19. The handshake
        # passes (19 == 19); the plugin's own record says 18.1.3.
        self.lab.pins([self.lab.pin('clang', 19, self.clang_plugin)])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='clang-19')
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn('built against clang 18.1.3', r.stderr)
        self.assertFalse(self.lab.exists('t.o'))
        self.assertTrue(self.lab.exists('t.o.vgpin-rejected'))


class ThePluginPin(Base):
    def test_sha256_mismatch_is_refused_before_compiling(self):
        self.lab.pins([dict(self.lab.pin('clang', 18, self.clang_plugin), sha256='0' * 64)])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 4)
        self.assertIn('sha256', r.stderr)
        self.assertEqual(self.lab.compiles(), [])

    def test_a_plugin_changed_after_pinning_is_refused(self):
        with open(self.clang_plugin, 'a', encoding='utf-8') as f:
            f.write(' ')
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.lab.compiles(), [])

    def test_a_missing_plugin_is_refused(self):
        entry = self.lab.pin('clang', 18, self.clang_plugin)
        entry['plugin'] = os.path.join(self.lab.root, 'nonexistent', 'libWipePin.so')
        self.lab.pins([entry])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.lab.compiles(), [])

    def test_no_pins_file_is_refused(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], drop=('VGPIN_PINS',))
        self.assertEqual(r.returncode, 4)
        self.assertIn('VGPIN_PINS is not set', r.stderr)

    def test_the_example_pins_file_is_refused_as_it_stands(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VGPIN_PINS': EXAMPLE_PINS})
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.lab.compiles(), [])

    def test_a_bad_mode_value_is_refused(self):
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_MODE': 'warning'})
        self.assertEqual(r.returncode, 4)
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_VERBOSE': 'yes'})
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.lab.compiles(), [])

    def test_the_wrapper_will_not_run_itself(self):
        link = self.lab.install_wrapper_copy('vgpin-x')
        r = self.lab.run(['-O2', '-c', 't.c'], cc=os.path.join(self.lab.bin, 'vgpin-cc'), argv0=link)
        self.assertEqual(r.returncode, 4)
        self.assertIn('resolves to this wrapper', r.stderr)


class TheRecord(Base):
    def assert_withheld(self, r, out='t.o', code=3):
        self.assertEqual(r.returncode, code, r.stderr)
        self.assertFalse(self.lab.exists(out))
        self.assertTrue(self.lab.exists(out + '.vgpin-rejected'))

    def test_fortify_wrapper_left_alone_is_withheld(self):
        self.set_plugin('clang', record('clang', unhandled={'libcallMemset': 0, 'memsetChk': 1, 'nonZeroFill': 0,
                                                            'atomicMemset': 0, 'inlineWrapperMemset': 1}))
        r = self.lab.run(['-O2', '-D_FORTIFY_SOURCE=2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn('inlineWrapperMemset=1', r.stderr)
        self.assertNotIn('memsetChk=1', r.stderr)

    def test_warn_keeps_the_output_and_says_so(self):
        self.set_plugin('clang', record('clang', unhandled={'libcallMemset': 0, 'memsetChk': 1, 'nonZeroFill': 0,
                                                            'atomicMemset': 0, 'inlineWrapperMemset': 1}))
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_MODE': 'warn'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.lab.exists('t.o'))
        self.assertIn('VG_PIN_MODE=warn', r.stderr)

    def test_gcc_memsetchk_from_the_fortify_wrapper_body_does_not_stop_it(self):
        self.set_plugin('gcc', record('gcc', unhandled={'libcallMemset': 0, 'memsetChk': 1, 'nonZeroFill': 0,
                                                        'atomicMemset': 0, 'inlineWrapperMemset': 0}))
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='gcc-13')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_ignore_list_comes_from_the_pins_file(self):
        self.lab.pins([self.lab.pin('gcc', 13, self.lab.plugin('g.so', record(
            'gcc', unhandled={'libcallMemset': 0, 'memsetChk': 1, 'nonZeroFill': 0, 'atomicMemset': 0,
                              'inlineWrapperMemset': 0})))], unhandledIgnore=[])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='gcc-13')
        self.assert_withheld(r)
        self.assertIn('memsetChk=1', r.stderr)

    def test_libcall_memset_is_withheld(self):
        self.set_plugin('gcc', record('gcc', unhandled={'libcallMemset': 1, 'memsetChk': 0, 'nonZeroFill': 0,
                                                        'atomicMemset': 0, 'inlineWrapperMemset': 0}))
        r = self.lab.run(['-O2', '-fno-builtin', '-c', 't.c', '-o', 't.o'], cc='gcc-13')
        self.assert_withheld(r)

    def test_no_record_because_the_plugin_refused(self):
        self.set_plugin('clang', None, refuse='WPIN_DRY_RUN is neither 0 nor 1')
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn('wrote no record', r.stderr)
        self.assertIn('WipePin: refusing to install', r.stderr)

    def test_no_record_in_warn_mode_keeps_the_output(self):
        self.set_plugin('clang', None, refuse='x')
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_MODE': 'warn'})
        self.assertEqual(r.returncode, 0)
        self.assertTrue(self.lab.exists('t.o'))

    def test_a_dry_run_record_is_withheld(self):
        self.set_plugin('clang', record('clang', dryRun=True, pinnedCount=0))
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']))

    def test_eligible_sites_left_unpinned_are_withheld(self):
        self.set_plugin('gcc', record('gcc', pinnedCount=0, wouldPinCount=1))
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='gcc-13')
        self.assert_withheld(r)
        self.assertIn('were not pinned', r.stderr)

    def test_nothing_to_pin_passes_unless_a_repair_is_required(self):
        empty = record('clang', pinned=[], pinnedCount=0, wouldPinCount=0,
                       seen={'zeroFillMemsetInScope': 0, 'zeroFillMemsetInModule': 0})
        self.set_plugin('clang', empty)
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_REQUIRE_REPAIR': '1'})
        self.assert_withheld(r)
        self.assertIn('nothing was repaired', r.stderr)

    def test_wrong_component_or_scope_is_withheld(self):
        self.set_plugin('clang', record('gcc'))
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']))
        self.set_plugin('clang', record('clang', scope='functions'))
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']))

    def test_unreadable_and_unknown_records_are_withheld(self):
        self.set_plugin('clang', None, raw='{not json')
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']))
        self.set_plugin('clang', record('clang', schemaVersion='wipe-pin-v1'))
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn("'wipe-pin-v1'", r.stderr)
        self.set_plugin('clang', record('clang', unhandled={'libcallMemset': 'one'}))
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']))

    def test_a_v2_record_is_withheld(self):
        # v3 only (RECORD_VERSIONS): a plugin built from a commit that writes v2
        # (22e7222 and earlier) is refused.
        for fam, cc in (('clang', 'clang-18'), ('gcc', 'gcc-13')):
            self.set_plugin(fam, record_v2(fam))
            r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc=cc)
            self.assert_withheld(r)
            self.assertIn("'wipe-pin-v2', not one of wipe-pin-v3", r.stderr)

    def test_a_v3_record_without_its_host_block_is_withheld(self):
        rec = record('clang')
        del rec['host']
        self.set_plugin('clang', rec)
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn('no host object', r.stderr)

    def test_a_v3_record_is_read(self):
        self.set_plugin('clang', record_v3('clang'))
        self.assertEqual(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']).returncode, 0)
        self.set_plugin('gcc', record_v3('gcc'))
        self.assertEqual(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], cc='gcc-13').returncode, 0)

    def test_v3_unhandled_counters_stop_it(self):
        for key in ('bzeroCall', 'inlineWrapperBzero', 'zeroGlobalCopy', 'zeroGlobalCopyCall'):
            rec = record_v3('clang')
            rec['unhandled'][key] = 1
            self.set_plugin('clang', rec)
            r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
            self.assert_withheld(r)
            self.assertIn(f'{key}=1', r.stderr)

    def test_an_unhandled_counter_nobody_has_named_yet_stops_it(self):
        rec = record_v3('clang')
        rec['unhandled']['someFutureShape'] = 2
        self.set_plugin('clang', rec)
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']))

    def test_barrier_sites_left_unbarriered_are_withheld(self):
        self.set_plugin('clang', record_v3('clang', barrierCalls={'sites': [], 'barrierCount': 0,
                                                                  'wouldBarrierCount': 2}))
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn('barrierCalls were not repaired', r.stderr)

    def test_barriers_count_as_repairs(self):
        rec = record_v3('clang', pinned=[], pinnedCount=0, wouldPinCount=0,
                        barrierCalls={'sites': [], 'barrierCount': 1, 'wouldBarrierCount': 1})
        self.set_plugin('clang', rec)
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'], extra={'VG_PIN_REQUIRE_REPAIR': '1'})
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_host_major_that_disagrees_is_withheld(self):
        for key in ('identMajor', 'builtMajor'):
            rec = record_v3('clang')
            rec['host'][key] = 19
            self.set_plugin('clang', rec)
            r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
            self.assert_withheld(r)
            self.assertIn(f'host.{key} 19', r.stderr)

    def test_a_module_without_an_ident_is_not_refused(self):
        # wipe-pin.md 14.7: nothing to compare is checked: false, not a refusal (D26).
        rec = record_v3('clang')
        rec['host'].update(ident=None, identMajor=None, checked=False)
        self.set_plugin('clang', rec)
        self.assertEqual(self.lab.run(['-O2', '-c', 't.c', '-o', 't.o']).returncode, 0)

    def test_a_v3_plugin_with_the_switch_on_passes(self):
        rec = record_v3('clang', pinned=[], pinnedCount=0, wouldPinCount=0,
                        barrierCalls={'enabled': True, 'sites': [{'function': 'f', 'callee': 'memset.inline',
                                                                  'lengthBytes': 32, 'line': None}],
                                      'barrierCount': 1, 'wouldBarrierCount': 1})
        path = self.lab.plugin('v3.so', rec)
        self.lab.pins([self.lab.pin('clang', 18, path, env={'WPIN_BARRIER_CALLS': '1'})])
        r = self.lab.run(['-O2', '-D_FORTIFY_SOURCE=2', '-c', 't.c', '-o', 't.o'],
                         extra={'VG_PIN_REQUIRE_REPAIR': '1'})
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_v3_plugin_whose_block_says_the_switch_was_off_is_withheld(self):
        path = self.lab.plugin('v3off.so', record_v3('clang'))
        self.lab.pins([self.lab.pin('clang', 18, path, env={'WPIN_ZERO_COPY': '1'})])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn('zeroCopy.enabled false', r.stderr)

    def test_a_switch_the_plugin_does_not_implement_is_withheld(self):
        # A writer that does not know the switch ignores WPIN_BARRIER_CALLS and
        # writes no barrierCalls object.
        rec = record('clang')
        del rec['barrierCalls']
        path = self.lab.plugin('old.so', rec)
        self.lab.pins([self.lab.pin('clang', 18, path, env={'WPIN_BARRIER_CALLS': '1'})])
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 't.o'])
        self.assert_withheld(r)
        self.assertIn('does not implement the switch', r.stderr)

    def test_default_output_names_are_withheld(self):
        self.set_plugin('clang', None, refuse='x')
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c']), out='t.o')
        self.assert_withheld(self.lab.run(['-O2', '-S', 't.c']), out='t.s')
        self.assert_withheld(self.lab.run(['-O2', '-c', '-S', 't.c']), out='t.s')
        self.assert_withheld(self.lab.run(['-O2', 't.c']), out='a.out')
        self.assert_withheld(self.lab.run(['-O2', '-c', 't.c', '-ox.o']), out='x.o')

    def test_a_symlinked_output_is_moved_as_a_link(self):
        self.set_plugin('clang', None, refuse='x')
        real = os.path.join(self.lab.work, 'real.o')
        os.symlink('real.o', os.path.join(self.lab.work, 'link.o'))
        r = self.lab.run(['-O2', '-c', 't.c', '-o', 'link.o'])
        self.assertEqual(r.returncode, 3)
        self.assertFalse(self.lab.exists('link.o'))
        self.assertTrue(os.path.islink(os.path.join(self.lab.work, 'link.o.vgpin-rejected')))
        self.assertTrue(os.path.isfile(real))


class TheCommandLine(Base):
    def test_two_sources_are_refused_before_compiling(self):
        r = self.lab.run(['-O2', '-c', 't.c', 'u.c'])
        self.assertEqual(r.returncode, 5)
        self.assertEqual(self.lab.calls(), [])

    def test_a_source_and_an_assembly_file_are_refused(self):
        self.lab.write('a.S', '\t.text\n')
        r = self.lab.run(['-O2', '-c', 't.c', 'a.S'])
        self.assertEqual(r.returncode, 5)
        self.assertEqual(self.lab.calls(), [])

    def test_output_to_stdout_is_refused(self):
        r = self.lab.run(['-O2', '-S', 't.c', '-o', '-'])
        self.assertEqual(r.returncode, 5)
        self.assertEqual(self.lab.calls(), [])

    def test_preprocess_and_dependency_only_pass_through_without_the_plugin(self):
        for args in (['-E', 't.c', '-o', 't.i'], ['-M', 't.c'], ['-MM', 't.c'], ['-fsyntax-only', 't.c']):
            r = self.lab.run(args, extra={'WPIN_OUT': '/tmp/x'})
            self.assertEqual(r.returncode, 0, (args, r.stderr))
        for c in self.lab.calls():
            self.assertFalse(any(a.startswith('-fpass-plugin=') for a in c['args']), c)
            self.assertEqual(c['wpin'], {}, c)

    def test_dependency_files_beside_a_compile_still_compile_with_the_plugin(self):
        r = self.lab.run(['-O2', '-MD', '-MF', 't.d', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.lab.compiles()[0]['args'][0].startswith('-fpass-plugin='))

    def test_version_and_help_pass_through_without_pins(self):
        for args in (['--version'], ['-dumpversion'], ['-###', '-c', 't.c'], ['--version', '-c', 't.c', '-o', 'p.o']):
            r = self.lab.run(args, drop=('VGPIN_PINS',))
            self.assertEqual(r.returncode, 0, (args, r.stderr))
        self.assertFalse(any(a.startswith('-fpass-plugin=') for c in self.lab.calls() for a in c['args']))

    def test_dash_v_with_a_source_compiles_with_the_plugin(self):
        r = self.lab.run(['-v', '-O2', '-c', 't.c', '-o', 't.o'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.lab.compiles()[0]['args'][0].startswith('-fpass-plugin='))

    def test_dash_v_alone_passes_through(self):
        r = self.lab.run(['-v'], drop=('VGPIN_PINS',))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_link_only_line_passes_through_without_the_plugin_or_wpin(self):
        self.lab.write('t.o', 'obj')
        r = self.lab.run(['t.o', '-o', 'app'], extra={'WPIN_OUT': '/tmp/x'}, drop=('VGPIN_PINS',))
        self.assertEqual(r.returncode, 0, r.stderr)
        (c,) = self.lab.calls()
        self.assertEqual(c['args'], ['t.o', '-o', 'app'])
        self.assertEqual(c['wpin'], {})

    def test_an_lto_link_line_never_gets_the_plugin_or_wpin_out(self):
        self.lab.write('t.o', 'obj')
        for cc in ('clang-18', 'gcc-13'):
            r = self.lab.run(['-flto', '-O2', 't.o', '-o', 'app'], cc=cc, extra={'WPIN_OUT': '/tmp/x'})
            self.assertEqual(r.returncode, 0, r.stderr)
        for c in self.lab.calls():
            self.assertFalse(any(a.startswith(('-fpass-plugin=', '-fplugin=')) for a in c['args']))
            self.assertEqual(c['wpin'], {})

    def test_an_lto_compile_step_gets_the_plugin(self):
        for cc in ('clang-18', 'gcc-13'):
            r = self.lab.run(['-flto', '-O2', '-c', 't.c', '-o', 't.o'], cc=cc)
            self.assertEqual(r.returncode, 0, (cc, r.stderr))
        self.assertEqual(len(self.lab.compiles()), 2)

    def test_gcc_lto_compile_and_link_on_one_line_is_refused(self):
        r = self.lab.run(['-flto', '-O2', 't.c', '-o', 'app'], cc='gcc-13')
        self.assertEqual(r.returncode, 5, r.stderr)
        self.assertEqual(self.lab.compiles(), [])
        r = self.lab.run(['-flto', '-fno-lto', '-O2', 't.c', '-o', 'app'], cc='gcc-13')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_clang_lto_compile_and_link_on_one_line_is_compiled(self):
        r = self.lab.run(['-flto=thin', '-O2', 't.c', '-o', 'app'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.lab.compiles()), 1)

    def test_assembly_only_passes_through(self):
        self.lab.write('a.S', '\t.text\n')
        r = self.lab.run(['-c', 'a.S', '-o', 'a.o'], drop=('VGPIN_PINS',))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lab.calls()[0]['args'], ['-c', 'a.S', '-o', 'a.o'])

    def test_standard_input_is_one_source(self):
        r = self.lab.run(['-O2', '-c', '-x', 'c', '-'], stdin=SRC)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.lab.exists('-.o'))
        self.set_plugin('clang', None, refuse='x')
        r = self.lab.run(['-O2', '-c', '-x', 'c', '-'], stdin=SRC)
        self.assertEqual(r.returncode, 3)
        self.assertTrue(self.lab.exists('-.o.vgpin-rejected'))

    def test_a_response_file_is_read_for_checking_and_passed_unexpanded(self):
        self.lab.write('one.rsp', '-O2 -c "t.c" -o t.o\n')
        r = self.lab.run(['@one.rsp'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lab.compiles()[0]['args'][1:], ['@one.rsp'])

    def test_two_sources_hidden_in_a_response_file_are_refused(self):
        self.lab.write('inner.rsp', 'u.c\n')
        self.lab.write('two.rsp', "-c t.c @inner.rsp\n")
        r = self.lab.run(['-O2', '@two.rsp'])
        self.assertEqual(r.returncode, 5)
        self.assertEqual(self.lab.calls(), [])

    def test_an_unreadable_response_file_is_refused(self):
        r = self.lab.run(['-O2', '-c', 't.c', '@missing.rsp'])
        self.assertEqual(r.returncode, 5)
        self.assertIn('could not be expanded', r.stderr)
        self.assertEqual(self.lab.calls(), [])


if __name__ == '__main__':
    unittest.main()
