/**
 * lib/scan.mjs counts the longest run of tracer bytes, and it is the JavaScript
 * half of a pair: the C observer counts the same thing over the same window and
 * the runner refuses a cell where the two disagree. These tests are what keeps
 * that pair honest, because a second implementation that is wrong in the same way
 * as the first is not a check.
 *
 * The cases below are the ones a naive implementation gets wrong: a fragment that
 * starts in the middle of the needle, a run that straddles the end of the
 * haystack, two runs where only the longer counts, and a search that quietly
 * returns a hit for an empty input.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { longestRun, longestRunOverSlots, hexToBytes, classify, needleSanity, agrees, PARTIAL_FLOOR, RESIDUE } from '../lib/scan.mjs';

const U = (...b) => new Uint8Array(b);
const needle = U(10, 11, 12, 13, 14, 15, 16, 17, 18, 19);

test('the whole needle is found, with its position', () => {
  const hay = U(0, 0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0);
  const r = longestRun(hay, needle);
  assert.equal(r.len, 10);
  assert.equal(r.hayOffset, 2);
  assert.equal(r.needleOffset, 0);
});

test('a fragment starting in the MIDDLE of the needle is found, which a prefix search would miss', () => {
  const hay = U(99, 14, 15, 16, 17, 18, 99);
  const r = longestRun(hay, needle);
  assert.equal(r.len, 5);
  assert.equal(r.needleOffset, 4, 'the run begins at needle[4], not at needle[0]');
});

test('a run that ends at the end of the haystack is not truncated by an off-by-one', () => {
  assert.equal(longestRun(U(0, 0, 16, 17, 18, 19), needle).len, 4);
  assert.equal(longestRun(U(10, 11, 12), needle).len, 3);
});

test('the LONGEST run wins, not the first', () => {
  const hay = U(10, 11, 0, 14, 15, 16, 17, 0);
  const r = longestRun(hay, needle);
  assert.equal(r.len, 4);
  assert.equal(r.hayOffset, 3);
});

test('an empty haystack, an empty needle or a missing argument is zero, never a hit', () => {
  assert.equal(longestRun(U(), needle).len, 0);
  assert.equal(longestRun(U(1, 2, 3), U()).len, 0);
  assert.equal(longestRun(null, needle).len, 0);
  assert.equal(longestRun(U(1, 2, 3), null).len, 0);
});

test('registers are scanned slot by slot, so a run cannot straddle two of them', () => {
  // Needle bytes 10..13 split across the tail of one register and the head of
  // the next. A concatenated search would report 4; the truth is 2 and 2.
  const slots = [U(0, 0, 0, 0, 0, 0, 10, 11), U(12, 13, 0, 0, 0, 0, 0, 0)];
  const r = longestRunOverSlots(slots, needle);
  assert.equal(r.len, 2);
  assert.ok(r.slot === 0 || r.slot === 1);
  assert.equal(longestRunOverSlots([], needle).len, 0);
  assert.equal(longestRunOverSlots(null, needle).slot, -1);
});

test('hexToBytes accepts clean hex and refuses everything else', () => {
  assert.deepEqual([...hexToBytes('00ff10')], [0, 255, 16]);
  assert.deepEqual([...hexToBytes('0Aff')], [10, 255]);
  for (const bad of ['', 'abc', 'zz', '0x00', null, 42]) assert.equal(hexToBytes(bad).length, 0);
});

test('classify uses the stated floor and nothing else', () => {
  assert.equal(classify(32, 32), 'FULL');
  assert.equal(classify(33, 32), 'FULL', 'a run longer than the needle is still FULL, not an error');
  assert.equal(classify(31, 32), 'PARTIAL');
  assert.equal(classify(PARTIAL_FLOOR, 32), 'PARTIAL');
  assert.equal(classify(PARTIAL_FLOOR - 1, 32), 'NONE');
  assert.equal(classify(0, 32), 'NONE');
  assert.equal(classify(4, 32, 4), 'PARTIAL', 'the floor is a parameter, so a run can be regraded without re-measuring');
  assert.throws(() => classify(1.5, 32), TypeError);
  assert.throws(() => classify(4, 0), TypeError);
});

test('the residue vocabulary carries NOT_OBSERVED and it is not one of the three readings', () => {
  assert.deepEqual([...RESIDUE], ['NONE', 'PARTIAL', 'FULL', 'NOT_OBSERVED']);
});

test('needleSanity rejects the draws that would make a chance hit plausible', () => {
  assert.equal(needleSanity(new Uint8Array(32).fill(7)).ok, false, 'a constant tracer matches any zeroed stack region');
  assert.equal(needleSanity(U(1, 2, 3, 4)).ok, false, 'shorter than twice the floor');
  const repeated = new Uint8Array(32);
  for (let i = 0; i < 32; i++) repeated[i] = i % 8;
  assert.equal(needleSanity(repeated).ok, false, 'a repeated 8-byte block makes one hit look like two');
  const ok = new Uint8Array(32);
  for (let i = 0; i < 32; i++) ok[i] = (i * 37 + 11) & 0xff;
  assert.equal(needleSanity(ok).ok, true);
  assert.equal(needleSanity('not bytes').ok, false);
});

test('agrees is an integer identity, so a missing count never reads as agreement', () => {
  assert.equal(agrees(8, 8), true);
  assert.equal(agrees(8, 9), false);
  assert.equal(agrees(null, null), false, 'two absent counts are not two agreeing counts');
  assert.equal(agrees(undefined, 0), false);
});
