#!/usr/bin/env python3
"""Compare a WipePin record with a WipeWitness record of the same compile.

    python3 compiler/wipe-witness/scripts/witness_check.py \
        --pin <wipe-pin-v3 record> --witness <wipe-witness-v1 record> [--json]

The question is narrow. For every function WipePin's record says it placed a
repair in (a pinned memset, a barrier after a call, a repaired copy from an
all-zero constant, a buffer barrier), is that function still a definition at
the end of the optimisation pipeline with no WipePin barrier and no volatile
zero memset left in it? That is the shape of a repair the optimiser deleted
after WipePin had already written "repaired" into its record.

The counts are never compared for equality. The optimiser can hoist two
barriers into one (one record entry fewer than the record says) and inlining
can copy a callee's barriers into the caller (more): only "placed, still
defined, and zero left" is reported.

Exit codes (the convention of the repository's fixture-loop checkers, plus 4):
  0  every function WipePin placed a repair in still has at least one barrier
     or volatile zero memset at the end, or is no longer a definition there
     (inlined or removed; reported, not judged)
  2  at least one function is SILENT: placed, still defined, zero left
  3  the pair cannot be judged: a record is missing, unreadable or of the wrong
     shape, the two records describe different compiles, the witness ran before
     WipePin (or could not tell), the end of the pipeline was not reached, or
     the witness's start count is below what WipePin says it placed
  4  WipePin placed nothing (a dry run, or nothing in scope): nothing to judge

What this cannot see is in ../README.md: code generation, who placed a
barrier, and whether a barrier is on the path of the wipe it was meant for.
"""

import argparse
import json
import sys

PIN_SCHEMA = 'wipe-pin-v3'
WITNESS_SCHEMA = 'wipe-witness-v1'

# Which witness pairs with which repair plugin, and the key that names the
# major version the witness was built against.
PAIRS = {
    'WipePin': ('WipeWitness', 'llvmMajor', 'llvmVersion'),
    'WipePinGcc': ('WipeWitnessGcc', 'gccMajor', 'gccVersion'),
}
COUNT_KEYS = ('barriers', 'otherMemoryAsm', 'volatileZeroMemsets', 'volatileZeroStores')
END_STATES = ('defined', 'declaration', 'absent')
ORDERS = ('wipepin-first', 'witness-first', 'no-wipepin', 'unknown')

EXIT_OK, EXIT_SILENT, EXIT_CANNOT, EXIT_NOTHING = 0, 2, 3, 4


class Refusal(Exception):
    """The pair cannot be judged; the message says why."""


def _int(v, where):
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise Refusal('%s is not a non-negative integer' % where)
    return v


def _str(v, where):
    if not isinstance(v, str):
        raise Refusal('%s is not a string' % where)
    return v


def _bool(v, where):
    if not isinstance(v, bool):
        raise Refusal('%s is not a boolean' % where)
    return v


def _obj(v, where):
    if not isinstance(v, dict):
        raise Refusal('%s is not an object' % where)
    return v


def _list(v, where):
    if not isinstance(v, list):
        raise Refusal('%s is not a list' % where)
    return v


def load_json(path, what):
    """The parsed object at `path`. Bytes that are not UTF-8 are kept (a
    function name is a byte string in both writers), so a name compares equal
    between the two records whatever it holds."""
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError as e:
        raise Refusal('no %s record at the path given (%s)' % (what, type(e).__name__))
    if not raw.strip():
        raise Refusal('the %s record is empty' % what)
    try:
        return json.loads(raw.decode('utf-8', errors='surrogateescape'))
    except ValueError as e:
        raise Refusal('the %s record is not JSON (%s)' % (what, e))


def read_pin(rec):
    """What the checker needs from a wipe-pin-v3 record: the component, the
    module, the major version the plugin was built against, and how many
    repairs it placed in each function. Only the fields read here are checked;
    the full reader is compiler/eval/repair-loop/lib/pin-record.mjs."""
    _obj(rec, 'the WipePin record')
    if rec.get('schemaVersion') != PIN_SCHEMA:
        raise Refusal('the WipePin record\'s schemaVersion is %r, not %r'
                      % (rec.get('schemaVersion'), PIN_SCHEMA))
    component = _str(rec.get('component'), 'component')
    if component not in PAIRS:
        raise Refusal('the WipePin record\'s component %r is not one of %s'
                      % (component, ', '.join(sorted(PAIRS))))
    module = _str(rec.get('module'), 'module')
    dry = _bool(rec.get('dryRun'), 'dryRun')
    host = _obj(rec.get('host'), 'host')
    built_major = _int(host.get('builtMajor'), 'host.builtMajor')
    ident_major = host.get('identMajor')
    if ident_major is not None:
        _int(ident_major, 'host.identMajor')

    pinned = _list(rec.get('pinned'), 'pinned')
    pinned_count = _int(rec.get('pinnedCount'), 'pinnedCount')
    fresh = []
    for i, s in enumerate(pinned):
        _obj(s, 'pinned[%d]' % i)
        fn = _str(s.get('function'), 'pinned[%d].function' % i)
        if not _bool(s.get('alreadyVolatile'), 'pinned[%d].alreadyVolatile' % i):
            fresh.append(fn)

    def block(name, count_key):
        b = _obj(rec.get(name), name)
        enabled = _bool(b.get('enabled'), name + '.enabled')
        sites = _list(b.get('sites'), name + '.sites')
        n = _int(b.get(count_key), '%s.%s' % (name, count_key))
        fns = []
        for i, s in enumerate(sites):
            _obj(s, '%s.sites[%d]' % (name, i))
            fns.append(_str(s.get('function'), '%s.sites[%d].function' % (name, i)))
        if not enabled and (sites or n):
            raise Refusal('%s is not enabled but lists sites or counts repairs' % name)
        return n, fns

    barrier_n, barrier_fns = block('barrierCalls', 'barrierCount')
    copy_n, copy_fns = block('zeroCopy', 'repairedCount')
    buffer_n, buffer_fns = block('bufferBarriers', 'count')

    placed = {}
    order = []

    def add(fns):
        for fn in fns:
            if fn not in placed:
                placed[fn] = 0
                order.append(fn)
            placed[fn] += 1

    if dry:
        if pinned_count or barrier_n or copy_n or buffer_n:
            raise Refusal('the WipePin record is a dry run and counts repairs')
    else:
        # A record whose counts disagree with its lists describes something
        # this checker cannot pair with a count of the IR.
        if pinned_count != len(fresh):
            raise Refusal('pinnedCount %d is not the %d pinned[] site(s) that were not '
                          'already volatile' % (pinned_count, len(fresh)))
        if barrier_n != len(barrier_fns):
            raise Refusal('barrierCalls.barrierCount %d is not the %d site(s) listed'
                          % (barrier_n, len(barrier_fns)))
        if copy_n != len(copy_fns):
            raise Refusal('zeroCopy.repairedCount %d is not the %d site(s) listed'
                          % (copy_n, len(copy_fns)))
        if buffer_n != len(buffer_fns):
            raise Refusal('bufferBarriers.count %d is not the %d site(s) listed'
                          % (buffer_n, len(buffer_fns)))
        add(fresh)
        add(barrier_fns)
        add(copy_fns)
        add(buffer_fns)
    return {
        'component': component,
        'module': module,
        'builtMajor': built_major,
        'identMajor': ident_major,
        'dryRun': dry,
        'placed': placed,
        'order': order,
    }


def _counts(v, where):
    _obj(v, where)
    if set(v) != set(COUNT_KEYS):
        raise Refusal('%s has keys %s, not %s' % (where, sorted(v), list(COUNT_KEYS)))
    return {k: _int(v[k], '%s.%s' % (where, k)) for k in COUNT_KEYS}


def read_witness(rec):
    """A wipe-witness-v1 record, read strictly: an unknown or missing key, a
    wrong type, a duplicate function or an end that contradicts endState is a
    refusal."""
    _obj(rec, 'the witness record')
    if rec.get('schemaVersion') != WITNESS_SCHEMA:
        raise Refusal('the witness record\'s schemaVersion is %r, not %r'
                      % (rec.get('schemaVersion'), WITNESS_SCHEMA))
    component = _str(rec.get('component'), 'component')
    by_witness = {w: (major, version) for (w, major, version) in PAIRS.values()}
    if component not in by_witness:
        raise Refusal('the witness record\'s component %r is not one of %s'
                      % (component, ', '.join(sorted(by_witness))))
    major_key, version_key = by_witness[component]
    keys = {'schemaVersion', 'component', 'module', 'ident', 'identMajor', major_key,
            version_key, 'optLevel', 'order', 'endReached', 'functions'}
    if set(rec) != keys:
        extra = sorted(set(rec) - keys)
        missing = sorted(keys - set(rec))
        raise Refusal('the witness record has unknown key(s) %s and lacks %s' % (extra, missing))
    module = _str(rec['module'], 'module')
    if rec['ident'] is not None:
        _str(rec['ident'], 'ident')
    ident_major = rec['identMajor']
    if ident_major is not None:
        _int(ident_major, 'identMajor')
    built_major = _int(rec[major_key], major_key)
    _str(rec[version_key], version_key)
    opt = _obj(rec['optLevel'], 'optLevel')
    if set(opt) != {'speedup', 'size'}:
        raise Refusal('optLevel has keys %s, not speedup and size' % sorted(opt))
    _int(opt['speedup'], 'optLevel.speedup')
    _int(opt['size'], 'optLevel.size')
    order = _str(rec['order'], 'order')
    if order not in ORDERS:
        raise Refusal('order %r is not one of %s' % (order, ', '.join(ORDERS)))
    end_reached = _bool(rec['endReached'], 'endReached')
    functions = {}
    for i, f in enumerate(_list(rec['functions'], 'functions')):
        where = 'functions[%d]' % i
        _obj(f, where)
        if set(f) != {'name', 'start', 'end', 'endState'}:
            raise Refusal('%s has keys %s, not name, start, end, endState' % (where, sorted(f)))
        name = _str(f['name'], where + '.name')
        if name in functions:
            raise Refusal('function %r appears twice in the witness record' % name)
        start = None if f['start'] is None else _counts(f['start'], where + '.start')
        state = f['endState']
        if end_reached:
            if state not in END_STATES:
                raise Refusal('%s.endState %r is not one of %s' % (where, state, ', '.join(END_STATES)))
            if (f['end'] is None) != (state != 'defined'):
                raise Refusal('%s: end is %s but endState is %r'
                              % (where, 'null' if f['end'] is None else 'counted', state))
            if start is None and state != 'defined':
                raise Refusal('%s has neither a start count nor a definition at the end' % where)
        else:
            if state is not None or f['end'] is not None:
                raise Refusal('%s has an end although endReached is false' % where)
        end = None if f['end'] is None else _counts(f['end'], where + '.end')
        functions[name] = {'start': start, 'end': end, 'endState': state}
    return {
        'component': component,
        'module': module,
        'identMajor': ident_major,
        'builtMajor': built_major,
        'order': order,
        'endReached': end_reached,
        'functions': functions,
    }


def kept(counts):
    """What counts as "something of the repair is left": a WipePin-shaped
    barrier or a volatile zero memset. A volatile zero store is not a shape
    either repair plugin makes, so it does not count."""
    return counts['barriers'] + counts['volatileZeroMemsets']


def judge(pin, wit):
    """(exit code, report lines, summary) for one pair of read records."""
    expected_witness = PAIRS[pin['component']][0]
    if wit['component'] != expected_witness:
        raise Refusal('a %s record pairs with a %s record, not %s'
                      % (pin['component'], expected_witness, wit['component']))
    if pin['module'] != wit['module']:
        raise Refusal('the records describe different modules (%r and %r)'
                      % (pin['module'], wit['module']))
    if pin['builtMajor'] != wit['builtMajor']:
        raise Refusal('WipePin was built against major version %d and the witness against %d'
                      % (pin['builtMajor'], wit['builtMajor']))
    if (pin['identMajor'] is not None and wit['identMajor'] is not None
            and pin['identMajor'] != wit['identMajor']):
        raise Refusal('the records name different producers (major %d and %d)'
                      % (pin['identMajor'], wit['identMajor']))
    if wit['order'] != 'wipepin-first':
        why = {
            'witness-first': 'the witness ran before WipePin at the start of the pipeline '
                             '(load WipePin first)',
            'no-wipepin': 'the witness saw no WipePin pass run in this compile',
            'unknown': 'the witness could not see the order of the passes',
        }[wit['order']]
        raise Refusal('order %r: %s' % (wit['order'], why))
    if not wit['endReached']:
        raise Refusal('the witness record says the end of the pipeline was not reached')

    lines = []
    summary = {'module': pin['module'], 'silent': [], 'ok': [], 'notJudged': []}
    if not pin['placed']:
        lines.append('witness-check: %s: WipePin placed nothing%s; nothing to judge'
                     % (pin['module'], ' (a dry run)' if pin['dryRun'] else ''))
        return EXIT_NOTHING, lines, summary

    # The start count is taken directly after WipePin's pass: whatever WipePin
    # placed is there, plus whatever the source already had. Fewer than placed
    # means the start count is not of WipePin's output.
    for fn in pin['order']:
        f = wit['functions'].get(fn)
        if f is None or f['start'] is None:
            raise Refusal('WipePin placed %d repair(s) in %r and the witness saw no such '
                          'function at the start' % (pin['placed'][fn], fn))
        if kept(f['start']) < pin['placed'][fn]:
            raise Refusal('%r: WipePin placed %d repair(s) and the witness counted %d at the '
                          'start (barriers + volatile zero memsets); the start count is not of '
                          'WipePin\'s output' % (fn, pin['placed'][fn], kept(f['start'])))

    for fn in pin['order']:
        f = wit['functions'][fn]
        n = pin['placed'][fn]
        if f['endState'] != 'defined':
            lines.append('witness-check: %s: %s: placed %d; at the end: %s: not judged '
                         '(not a definition at the end: inlined, or removed)'
                         % (pin['module'], fn, n, f['endState']))
            summary['notJudged'].append(fn)
            continue
        e = f['end']
        state = 'SILENT' if kept(e) == 0 else 'ok'
        lines.append('witness-check: %s: %s: placed %d; at the end: defined, barriers %d, '
                     'volatile zero memsets %d: %s'
                     % (pin['module'], fn, n, e['barriers'], e['volatileZeroMemsets'], state))
        summary['silent' if state == 'SILENT' else 'ok'].append(fn)
    code = EXIT_SILENT if summary['silent'] else EXIT_OK
    lines.append('witness-check: %s: silent %d, ok %d, not judged %d'
                 % (pin['module'], len(summary['silent']), len(summary['ok']),
                    len(summary['notJudged'])))
    return code, lines, summary


def check_files(pin_path, witness_path):
    """(exit code, report lines, summary or None) for two record files."""
    try:
        pin = read_pin(load_json(pin_path, 'WipePin'))
        wit = read_witness(load_json(witness_path, 'witness'))
        return judge(pin, wit)
    except Refusal as r:
        return EXIT_CANNOT, ['witness-check: cannot judge: %s' % r], None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--pin', required=True, help='the wipe-pin-v3 record (WPIN_OUT)')
    ap.add_argument('--witness', required=True, help='the wipe-witness-v1 record (WWIT_OUT)')
    ap.add_argument('--json', action='store_true', help='print one JSON object instead of lines')
    args = ap.parse_args(argv)
    code, lines, summary = check_files(args.pin, args.witness)
    if args.json:
        print(json.dumps({'exit': code, 'lines': lines, 'summary': summary}, sort_keys=True))
    else:
        for line in lines:
            print(line)
    return code


if __name__ == '__main__':
    sys.exit(main())
