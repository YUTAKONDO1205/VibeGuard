import test from 'node:test';
import assert from 'node:assert/strict';

import { parseMap, looksLikeLldMap, inputDefiningAddress } from '../lib/map-parse.mjs';
import { fixture } from './helpers.mjs';

const neg = parseMap(fixture('neg.map.txt'));
const pos = parseMap(fixture('pos.map.txt'));
const arc = parseMap(fixture('arc.map.txt'));
const scr = parseMap(fixture('scr.map.txt'));

test('a captured map is recognised, and an ordinary text file is not', () => {
  assert.equal(looksLikeLldMap(fixture('neg.map.txt')), true);
  assert.equal(looksLikeLldMap('hello\nworld\n'), false);
  assert.equal(looksLikeLldMap(''), false);
});

test('every row of every captured map parses', () => {
  for (const [name, p] of [['neg', neg], ['pos', pos], ['arc', arc], ['scr', scr]]) {
    assert.deepEqual(p.malformed, [], `${name}.map had unparsed rows`);
    assert.equal(p.sawHeader, true, `${name}.map header`);
  }
});

// The indentation IS the grammar. If this ever regresses, output sections,
// input sections and symbols all collapse into one list and the parser reports
// symbol names as linker inputs — which the policy would then fail to
// authorise, producing a page of findings about things that are not files.
test('indentation separates output section, input section and symbol', () => {
  const text = neg.sections.find((s) => s.name === '.text');
  assert.ok(text, '.text output section');
  const scrt1 = text.contributions.find((c) => c.path.endsWith('Scrt1.o'));
  assert.ok(scrt1, 'Scrt1.o contributes to .text');
  assert.ok(scrt1.symbols.includes('_start'), '_start is a symbol of that contribution, not an input');
  assert.equal(neg.inputs.some((i) => i.path === '_start'), false, '_start must never be read as an input');
});

test('the negative fixture names the objects that were linked and no others', () => {
  const paths = neg.inputs.map((i) => i.path).sort();
  assert.ok(paths.includes('main.o'));
  assert.ok(paths.includes('helper.o'));
  assert.equal(paths.includes('rogue.o'), false);
  assert.ok(paths.includes('<internal>'), 'lld’s synthetic input is present and must be recognised as such');
});

test('the positive fixture names the unapproved object', () => {
  assert.ok(pos.inputs.some((i) => i.path === 'rogue.o'));
});

test('an archive member keeps both halves of its identity', () => {
  const member = arc.inputs.find((i) => i.path.includes('libarch.a'));
  assert.ok(member, 'the archive member is an input');
  assert.equal(member.path, './libarch.a(arch.o)');
  assert.ok(member.sections.includes('.text'));
});

test('.init_array contributions are attributed to the object that made them', () => {
  assert.equal(neg.initArray.present, true);
  const negFrom = neg.initArray.contributions.map((c) => c.path);
  assert.ok(negFrom.some((p) => p.endsWith('crtbeginS.o')));
  assert.ok(negFrom.includes('main.o'));
  assert.equal(negFrom.includes('rogue.o'), false);

  const posFrom = pos.initArray.contributions.map((c) => c.path);
  assert.ok(posFrom.includes('rogue.o'), 'the unapproved object runs code before main');
  assert.equal(pos.initArray.entriesBytes > neg.initArray.entriesBytes, true);
});

test('a section introduced by a linker script is visible as an output section', () => {
  assert.ok(scr.sections.some((s) => s.name === '.injected_note'));
  assert.equal(neg.sections.some((s) => s.name === '.injected_note'), false);
});

test('the entry address resolves to the symbol and the input that define it', () => {
  const at = inputDefiningAddress(neg, 0x1670);
  assert.deepEqual({ symbol: at.symbol, section: at.section }, { symbol: '_start', section: '.text' });
  assert.ok(at.input.endsWith('Scrt1.o'));
  assert.equal(inputDefiningAddress(neg, 0x7fffffff), null);
  assert.equal(inputDefiningAddress(neg, null), null);
});

// The hex/decimal split between the size and align columns is easy to get
// backwards, and getting it backwards produces sizes that are plausible.
test('sizes are read as hexadecimal and alignments as decimal', () => {
  const text = neg.sections.find((s) => s.name === '.text');
  assert.equal(text.align, 16, 'align 16 is decimal sixteen, not hex sixteen');
  assert.equal(text.vma, 0x1670);
  assert.equal(text.size, 0x174);
});

test('an unreadable row is reported rather than skipped', () => {
  const p = parseMap('             VMA              LMA     Size Align Out     In      Symbol\nthis is not a row\n');
  assert.equal(p.malformed.length, 1);
  assert.equal(p.malformed[0].line, 2);
});

test('a symbol row with no input section above it is malformed, not global', () => {
  const p = parseMap([
    '             VMA              LMA     Size Align Out     In      Symbol',
    '            1670             1670      174    16 .text',
    '            1670             1670       26     1                 _start',
  ].join('\n'));
  assert.equal(p.symbols.length, 0);
  assert.equal(p.malformed.length, 1);
});
