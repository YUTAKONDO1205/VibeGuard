#!/usr/bin/env python3
"""Unit tests for scripts/witness_check.py. No compiler is needed: the records
are built here, in the shapes WipePin and WipeWitness write.

    python3 compiler/wipe-witness/test/test_witness_check.py

Run as a file: the directory name is not a Python package name.
"""

import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'scripts'))
import witness_check as W  # noqa: E402


def counts(barriers=0, other=0, vmemset=0, vstore=0):
    return {'barriers': barriers, 'otherMemoryAsm': other,
            'volatileZeroMemsets': vmemset, 'volatileZeroStores': vstore}


def pin_record(component='WipePin', module='musttail.c', dry=False, pinned=(), barrier_sites=(),
               copy_sites=(), buffer_sites=(), built=18, ident=18):
    """A wipe-pin-v3 record with the fields the checker reads (and the others
    a writer always writes, so the shape is the real one). `pinned` is a list of
    (function, alreadyVolatile)."""
    sites = [{'function': f, 'index': i, 'lengthBytes': 32, 'destKind': 'alloca',
              'alreadyVolatile': av, 'followedByUse': False, 'line': 8}
             for i, (f, av) in enumerate(pinned)]
    fresh = sum(1 for (_, av) in pinned if not av)

    def blk(enabled, fns, count_key, extra):
        return dict({'enabled': enabled,
                     'sites': [{'function': f} for f in fns],
                     count_key: 0 if dry else len(fns)}, **extra)

    return {
        'schemaVersion': 'wipe-pin-v3', 'component': component, 'module': module,
        'optLevel': {'speedup': 2, 'size': 0}, 'scope': 'functions',
        'requested': ['handle'], 'resolution': [], 'dryRun': dry,
        'pinned': sites, 'pinnedCount': 0 if dry else fresh, 'wouldPinCount': fresh,
        'seen': {'zeroFillMemsetInScope': len(sites), 'zeroFillMemsetInModule': len(sites)},
        'unhandled': {},
        'barrierCalls': blk(bool(barrier_sites), barrier_sites, 'barrierCount',
                            {'wouldBarrierCount': len(barrier_sites)}),
        'zeroCopy': blk(bool(copy_sites), copy_sites, 'repairedCount',
                        {'wouldRepairCount': len(copy_sites)}),
        'bufferBarriers': blk(bool(buffer_sites), buffer_sites, 'count', {}),
        'host': {'ident': 'Ubuntu clang version %d.1.3' % ident, 'identMajor': ident,
                 'builtMajor': built, 'checked': True, 'intrinsicsCompared': 3},
    }


def fn(name, start=None, end=None, state='defined'):
    return {'name': name, 'start': start, 'end': end if state == 'defined' else None,
            'endState': state}


def witness_record(functions, module='musttail.c', order='wipepin-first', end_reached=True,
                   component='WipeWitness', major=18):
    rec = {'schemaVersion': 'wipe-witness-v1', 'component': component, 'module': module,
           'ident': 'Ubuntu clang version %d.1.3' % major, 'identMajor': major,
           'optLevel': {'speedup': 2, 'size': 0}, 'order': order, 'endReached': end_reached,
           'functions': functions}
    if component == 'WipeWitness':
        rec['llvmMajor'], rec['llvmVersion'] = major, '%d.1.3' % major
    else:
        rec['gccMajor'], rec['gccVersion'] = major, '%d.3.0' % major
    return rec


def run(pin, wit):
    return W.judge(W.read_pin(pin), W.read_witness(wit))


class TheRule(unittest.TestCase):
    def test_the_musttail_shape_of_the_old_build_is_silent(self):
        # The buffer barrier placed before a lifetime end in a block no path
        # reaches: counted at the start, gone at the end, function still there.
        code, lines, summary = run(pin_record(buffer_sites=['handle']),
                                   witness_record([fn('handle', counts(1), counts(0))]))
        self.assertEqual(code, W.EXIT_SILENT)
        self.assertEqual(summary['silent'], ['handle'])
        self.assertIn('SILENT', lines[0])

    def test_the_same_barrier_kept_is_ok(self):
        code, _, summary = run(pin_record(buffer_sites=['handle']),
                               witness_record([fn('handle', counts(1), counts(1))]))
        self.assertEqual((code, summary['ok']), (W.EXIT_OK, ['handle']))

    def test_a_pinned_memset_kept_as_a_volatile_memset_is_ok(self):
        code, _, _ = run(pin_record(pinned=[('handle', False)]),
                         witness_record([fn('handle', counts(vmemset=1), counts(vmemset=1))]))
        self.assertEqual(code, W.EXIT_OK)

    def test_fewer_left_than_placed_is_not_silent(self):
        # Two barriers hoisted into one block: the record says 2, the IR has 1.
        code, _, _ = run(pin_record(buffer_sites=['handle', 'handle']),
                         witness_record([fn('handle', counts(2), counts(1))]))
        self.assertEqual(code, W.EXIT_OK)

    def test_more_left_than_placed_is_not_silent(self):
        # Inlining copied a callee's barriers into the function.
        code, _, _ = run(pin_record(barrier_sites=['handle']),
                         witness_record([fn('handle', counts(1), counts(3))]))
        self.assertEqual(code, W.EXIT_OK)

    def test_a_volatile_store_does_not_count_as_kept(self):
        code, _, _ = run(pin_record(buffer_sites=['handle']),
                         witness_record([fn('handle', counts(1), counts(vstore=4))]))
        self.assertEqual(code, W.EXIT_SILENT)

    def test_another_memory_asm_does_not_count_as_kept(self):
        code, _, _ = run(pin_record(buffer_sites=['handle']),
                         witness_record([fn('handle', counts(1), counts(other=1))]))
        self.assertEqual(code, W.EXIT_SILENT)

    def test_a_function_inlined_away_is_not_judged(self):
        code, lines, summary = run(
            pin_record(buffer_sites=['wipe']),
            witness_record([fn('wipe', counts(1), state='absent'),
                            fn('handle', counts(0), counts(1))]))
        self.assertEqual(code, W.EXIT_OK)
        self.assertEqual(summary['notJudged'], ['wipe'])
        self.assertIn('not judged', lines[0])

    def test_a_function_left_as_a_declaration_is_not_judged(self):
        code, _, summary = run(pin_record(buffer_sites=['wipe']),
                               witness_record([fn('wipe', counts(1), state='declaration')]))
        self.assertEqual((code, summary['notJudged']), (W.EXIT_OK, ['wipe']))

    def test_a_function_without_a_placement_is_never_silent(self):
        code, _, summary = run(pin_record(buffer_sites=['handle']),
                               witness_record([fn('handle', counts(1), counts(1)),
                                               fn('other', counts(0), counts(0))]))
        self.assertEqual((code, summary['silent']), (W.EXIT_OK, []))

    def test_one_silent_function_among_kept_ones_is_silent(self):
        code, _, summary = run(pin_record(buffer_sites=['a', 'b']),
                               witness_record([fn('a', counts(1), counts(1)),
                                               fn('b', counts(1), counts(0))]))
        self.assertEqual((code, summary['silent'], summary['ok']), (W.EXIT_SILENT, ['b'], ['a']))

    def test_an_already_volatile_memset_is_not_a_placement(self):
        code, lines, _ = run(pin_record(pinned=[('handle', True)]),
                             witness_record([fn('handle', counts(vmemset=1), counts(0))]))
        self.assertEqual(code, W.EXIT_NOTHING)
        self.assertIn('placed nothing', lines[0])

    def test_a_dry_run_has_nothing_to_judge(self):
        code, lines, _ = run(pin_record(dry=True, buffer_sites=['handle']),
                             witness_record([fn('handle', counts(0), counts(0))]))
        self.assertEqual(code, W.EXIT_NOTHING)
        self.assertIn('dry run', lines[0])

    def test_every_kind_of_placement_counts(self):
        pin = W.read_pin(pin_record(pinned=[('p', False)], barrier_sites=['b'],
                                    copy_sites=['c'], buffer_sites=['f', 'p']))
        self.assertEqual(pin['placed'], {'p': 2, 'b': 1, 'c': 1, 'f': 1})
        self.assertEqual(pin['order'], ['p', 'b', 'c', 'f'])

    def test_the_gcc_pair_is_judged_by_the_same_rule(self):
        pin = pin_record(component='WipePinGcc', module='loop.c', buffer_sites=['handle'],
                         built=13, ident=13)
        code, _, summary = run(pin, witness_record([fn('handle', counts(1), counts(0))],
                                                   module='loop.c', component='WipeWitnessGcc',
                                                   major=13))
        self.assertEqual((code, summary['silent']), (W.EXIT_SILENT, ['handle']))
        code, _, _ = run(pin, witness_record([fn('handle', counts(1), counts(1))],
                                             module='loop.c', component='WipeWitnessGcc',
                                             major=13))
        self.assertEqual(code, W.EXIT_OK)

    def test_a_clone_made_by_the_optimiser_is_read(self):
        wit = W.read_witness(witness_record([fn('handle', counts(1), counts(0)),
                                             fn('handle.cold', None, counts(1))]))
        self.assertIsNone(wit['functions']['handle.cold']['start'])
        code, _, _ = W.judge(W.read_pin(pin_record(buffer_sites=['handle'])), wit)
        # The rule is per function name: the clone's barrier does not cover
        # the function the record names. Said in the README.
        self.assertEqual(code, W.EXIT_SILENT)


class Refusals(unittest.TestCase):
    def refused(self, pin, wit, fragment):
        with self.assertRaises(W.Refusal) as cm:
            run(pin, wit)
        self.assertIn(fragment, str(cm.exception))

    def test_the_witness_ran_first(self):
        self.refused(pin_record(buffer_sites=['handle']),
                     witness_record([fn('handle', counts(0), counts(1))], order='witness-first'),
                     'witness-first')

    def test_no_wipepin_pass_ran(self):
        self.refused(pin_record(buffer_sites=['handle']),
                     witness_record([fn('handle', counts(1), counts(1))], order='no-wipepin'),
                     'no WipePin pass')

    def test_the_order_could_not_be_seen(self):
        self.refused(pin_record(buffer_sites=['handle']),
                     witness_record([fn('handle', counts(1), counts(1))], order='unknown'),
                     'could not see')

    def test_the_end_was_not_reached(self):
        wit = witness_record([{'name': 'handle', 'start': counts(1), 'end': None,
                               'endState': None}], end_reached=False)
        self.refused(pin_record(buffer_sites=['handle']), wit, 'not reached')

    def test_different_modules(self):
        self.refused(pin_record(buffer_sites=['handle'], module='a.c'),
                     witness_record([fn('handle', counts(1), counts(1))], module='b.c'),
                     'different modules')

    def test_different_builds(self):
        self.refused(pin_record(buffer_sites=['handle'], built=19, ident=19),
                     witness_record([fn('handle', counts(1), counts(1))]),
                     'built against')

    def test_different_producers(self):
        self.refused(pin_record(buffer_sites=['handle'], ident=19),
                     witness_record([fn('handle', counts(1), counts(1))]),
                     'different producers')

    def test_the_wrong_witness_for_the_vendor(self):
        self.refused(pin_record(buffer_sites=['handle']),
                     witness_record([fn('handle', counts(1), counts(1))],
                                    component='WipeWitnessGcc', major=18),
                     'pairs with a WipeWitness record')

    def test_a_start_count_below_the_placements(self):
        # What a reversed order looks like when the order itself was not seen.
        self.refused(pin_record(buffer_sites=['handle']),
                     witness_record([fn('handle', counts(0), counts(1))]),
                     'start count is not of')

    def test_a_placement_in_a_function_the_witness_did_not_see(self):
        self.refused(pin_record(buffer_sites=['handle']),
                     witness_record([fn('other', counts(1), counts(1))]),
                     'saw no such function')

    def test_a_record_whose_count_contradicts_its_list(self):
        pin = pin_record(buffer_sites=['handle'])
        pin['bufferBarriers']['count'] = 2
        self.refused(pin, witness_record([fn('handle', counts(1), counts(1))]),
                     'bufferBarriers.count 2')

    def test_a_dry_run_that_counts_repairs(self):
        pin = pin_record(dry=True, pinned=[('handle', False)])
        pin['pinnedCount'] = 1
        self.refused(pin, witness_record([fn('handle', counts(1), counts(1))]), 'dry run')

    def test_a_disabled_block_with_sites(self):
        pin = pin_record(buffer_sites=['handle'])
        pin['bufferBarriers']['enabled'] = False
        self.refused(pin, witness_record([fn('handle', counts(1), counts(1))]), 'not enabled')

    def test_the_wrong_pin_schema(self):
        pin = pin_record(buffer_sites=['handle'])
        pin['schemaVersion'] = 'wipe-pin-v2'
        self.refused(pin, witness_record([fn('handle', counts(1), counts(1))]), 'wipe-pin-v2')


class WitnessShape(unittest.TestCase):
    def bad(self, mutate, fragment):
        rec = witness_record([fn('handle', counts(1), counts(1))])
        mutate(rec)
        with self.assertRaises(W.Refusal) as cm:
            W.read_witness(rec)
        self.assertIn(fragment, str(cm.exception))

    def test_an_unknown_key(self):
        self.bad(lambda r: r.update(extra=1), 'unknown key')

    def test_a_missing_key(self):
        self.bad(lambda r: r.pop('order'), 'lacks')

    def test_a_negative_count(self):
        self.bad(lambda r: r['functions'][0]['end'].update(barriers=-1), 'non-negative')

    def test_a_boolean_count(self):
        self.bad(lambda r: r['functions'][0]['end'].update(barriers=True), 'non-negative')

    def test_an_unknown_count_key(self):
        self.bad(lambda r: r['functions'][0]['end'].update(stores=0), 'has keys')

    def test_a_duplicate_function(self):
        self.bad(lambda r: r['functions'].append(copy.deepcopy(r['functions'][0])), 'twice')

    def test_an_end_count_on_an_absent_function(self):
        self.bad(lambda r: r['functions'][0].update(endState='absent'), 'endState')

    def test_a_defined_function_without_an_end_count(self):
        self.bad(lambda r: r['functions'][0].update(end=None), 'endState')

    def test_an_unknown_end_state(self):
        self.bad(lambda r: r['functions'][0].update(endState='inlined', end=None), 'not one of')

    def test_an_unknown_order(self):
        self.bad(lambda r: r.update(order='after'), 'not one of')

    def test_the_wrong_schema(self):
        self.bad(lambda r: r.update(schemaVersion='wipe-witness-v0'), 'wipe-witness-v0')

    def test_an_end_when_the_end_was_not_reached(self):
        self.bad(lambda r: r.update(endReached=False), 'endReached is false')

    def test_a_gcc_witness_with_the_clang_version_key(self):
        rec = witness_record([fn('handle', counts(1), counts(1))], component='WipeWitnessGcc',
                             major=13)
        rec['llvmMajor'] = rec.pop('gccMajor')
        with self.assertRaises(W.Refusal) as cm:
            W.read_witness(rec)
        self.assertIn('gccMajor', str(cm.exception))

    def test_an_unknown_witness_component(self):
        self.bad(lambda r: r.update(component='WipeWitnessMsvc'), 'not one of')


class Files(unittest.TestCase):
    """The command line, end to end, on files."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, obj_or_text):
        p = os.path.join(self.dir.name, name)
        with open(p, 'w', encoding='utf-8') as f:
            f.write(obj_or_text if isinstance(obj_or_text, str) else json.dumps(obj_or_text))
        return p

    def main(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = W.main(list(argv))
        return code, out.getvalue()

    def test_exit_2_and_the_line(self):
        p = self.write('p.json', pin_record(buffer_sites=['handle']))
        w = self.write('w.json', witness_record([fn('handle', counts(1), counts(0))]))
        code, out = self.main('--pin', p, '--witness', w)
        self.assertEqual(code, 2)
        self.assertIn('handle: placed 1; at the end: defined, barriers 0', out)

    def test_exit_0(self):
        p = self.write('p.json', pin_record(buffer_sites=['handle']))
        w = self.write('w.json', witness_record([fn('handle', counts(1), counts(1))]))
        self.assertEqual(self.main('--pin', p, '--witness', w)[0], 0)

    def test_exit_3_for_a_missing_record(self):
        p = self.write('p.json', pin_record(buffer_sites=['handle']))
        code, out = self.main('--pin', p, '--witness', os.path.join(self.dir.name, 'none.json'))
        self.assertEqual(code, 3)
        self.assertIn('no witness record', out)

    def test_exit_3_for_an_empty_record(self):
        p = self.write('p.json', pin_record(buffer_sites=['handle']))
        w = self.write('w.json', '')
        self.assertEqual(self.main('--pin', p, '--witness', w)[0], 3)

    def test_exit_3_for_text_that_is_not_json(self):
        p = self.write('p.json', '{"schemaVersion": "wipe-pin-v3",')
        w = self.write('w.json', witness_record([fn('handle', counts(1), counts(1))]))
        code, out = self.main('--pin', p, '--witness', w)
        self.assertEqual(code, 3)
        self.assertIn('not JSON', out)

    def test_exit_4(self):
        p = self.write('p.json', pin_record(dry=True, buffer_sites=['handle']))
        w = self.write('w.json', witness_record([fn('handle', counts(0), counts(0))]))
        self.assertEqual(self.main('--pin', p, '--witness', w)[0], 4)

    def test_json_output(self):
        p = self.write('p.json', pin_record(buffer_sites=['handle']))
        w = self.write('w.json', witness_record([fn('handle', counts(1), counts(0))]))
        code, out = self.main('--pin', p, '--witness', w, '--json')
        doc = json.loads(out)
        self.assertEqual((code, doc['exit'], doc['summary']['silent']), (2, 2, ['handle']))

    def test_a_name_that_is_not_utf8_matches_itself(self):
        # Both writers copy a function's name byte for byte.
        name = b'h\xffx'
        pin = json.dumps(pin_record(buffer_sites=['@@'])).encode().replace(b'@@', name)
        wit = json.dumps(witness_record([fn('@@', counts(1), counts(0))])).encode().replace(
            b'@@', name)
        pp = os.path.join(self.dir.name, 'p.json')
        wp = os.path.join(self.dir.name, 'w.json')
        with open(pp, 'wb') as f:
            f.write(pin)
        with open(wp, 'wb') as f:
            f.write(wit)
        code, _, summary = W.check_files(pp, wp)
        self.assertEqual(code, 2)
        self.assertEqual(len(summary['silent']), 1)


if __name__ == '__main__':
    unittest.main()
