// What the bundle observer must never do is report a clean artefact from a
// blind measurement. Most of what follows is that one property, approached from
// each direction a real build can be blind from.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  collectArtefacts,
  sourceMappingUrl,
  readSourceMap,
  republishedWitnesses,
  observeBundleDir,
  worstState,
} from '../src/bundle.mjs';

/** A minimal shipped file plus the map a bundler writes next to it. */
function fixture({ code, sourcesContent, mapName = 'app.js.map', writeMap = true, mapText }) {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  writeFileSync(join(dir, 'app.js'), `${code}\n//# sourceMappingURL=${mapName}\n`, 'utf8');
  if (writeMap) {
    writeFileSync(
      join(dir, mapName),
      mapText ?? JSON.stringify({ version: 3, sources: ['src/app.js'], sourcesContent }),
      'utf8',
    );
  }
  return dir;
}

test('sourceMappingURL: the last one wins, because that is the one a browser follows', () => {
  assert.equal(sourceMappingUrl('x\n//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map'), 'b.map');
  assert.equal(sourceMappingUrl('no map here'), null);
});

test('collectArtefacts finds code files and records what it could not read', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  mkdirSync(join(dir, 'nested'));
  writeFileSync(join(dir, 'a.js'), 'export const a = 1;', 'utf8');
  writeFileSync(join(dir, 'nested', 'b.mjs'), 'export const b = 2;', 'utf8');
  writeFileSync(join(dir, 'styles.css'), 'body{}', 'utf8');
  const { artefacts } = await collectArtefacts(dir);
  assert.deepEqual(
    artefacts.map((a) => a.relPath),
    ['a.js', 'nested/b.mjs'],
  );
  rmSync(dir, { recursive: true, force: true });
});

test('a source map that does not parse is NOT_OBSERVED, never clean', async () => {
  const dir = fixture({ code: 'function o(){}', sourcesContent: null, mapText: '{ not json' });
  const obs = await observeBundleDir(dir, { witnesses: ['isAdmin'], control: 'function' });
  assert.equal(obs.records.length, 1);
  const r = obs.records[0];
  assert.equal(r.state, 'NOT_OBSERVED');
  assert.equal(r.controlHeld, false);
  assert.match(r.why, /did not parse/);
  // The specific thing this test exists for: a broken map must not be able to
  // produce the finding polarity, because "we could not read it" and "the
  // defence is gone" would then print identically.
  assert.ok(r.witnesses.every((w) => w.state === 'NOT_OBSERVED'));
  rmSync(dir, { recursive: true, force: true });
});

test('a missing source map is NOT_OBSERVED, and says so', async () => {
  const dir = fixture({ code: 'function o(){}', sourcesContent: [], writeMap: false });
  const obs = await observeBundleDir(dir, { witnesses: ['isAdmin'], control: 'function' });
  assert.equal(obs.records[0].state, 'NOT_OBSERVED');
  assert.match(obs.records[0].why, /no source map/);
  rmSync(dir, { recursive: true, force: true });
});

test('a remote source map is not fetched, and the artefact is NOT_OBSERVED', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  writeFileSync(
    join(dir, 'app.js'),
    'function o(){}\n//# sourceMappingURL=https://cdn.example.com/app.js.map\n',
    'utf8',
  );
  const obs = await observeBundleDir(dir, { witnesses: ['isAdmin'], control: 'function' });
  assert.equal(obs.records[0].state, 'NOT_OBSERVED');
  assert.match(obs.records[0].why, /no network calls/);
  rmSync(dir, { recursive: true, force: true });
});

test('a dead control makes every verdict NOT_OBSERVED even when the map parsed', () => {
  const r = republishedWitnesses(
    'function o(){}',
    { sourcesContent: ['const x = 1;'] },
    ['isAdmin'],
    'THIS-TOKEN-IS-NOT-IN-THE-SOURCE',
  );
  assert.equal(r.controlHeld, false);
  assert.deepEqual(
    r.results.map((x) => x.state),
    ['NOT_OBSERVED'],
  );
});

test('the four cells are distinguished, and REINTRODUCED is the interesting one', () => {
  const code = 'function o(s){return s.stillHere}';
  const map = {
    sourcesContent: ['function o(s){ if(!s.isAdmin) throw 0; return s.stillHere }'],
  };
  const r = republishedWitnesses(code, map, ['stillHere', 'isAdmin', 'neverExisted'], 'function');
  assert.equal(r.controlHeld, true);
  const by = Object.fromEntries(r.results.map((x) => [x.witness, x.state]));
  assert.equal(by.stillHere, 'PRESENT');
  // Removed from the code that runs, and published next to it anyway.
  assert.equal(by.isAdmin, 'REINTRODUCED');
  assert.equal(by.neverExisted, 'ABSENT');
});

test('an inline base64 source map is read', async () => {
  const content = JSON.stringify({
    version: 3,
    sources: ['a.js'],
    sourcesContent: ['function f(){ if(!u.isAdmin) throw 0 }'],
  });
  const b64 = Buffer.from(content, 'utf8').toString('base64');
  const code = `function o(){}\n//# sourceMappingURL=data:application/json;base64,${b64}`;
  const { map, origin } = await readSourceMap('/nonexistent/app.js', code);
  assert.equal(origin, 'inline');
  assert.equal(map.sourcesContent.length, 1);
});

test('worstState ranks a republished defence above an unreadable measurement', () => {
  assert.equal(worstState(['PRESENT', 'NOT_OBSERVED', 'REINTRODUCED']), 'REINTRODUCED');
  assert.equal(worstState(['PRESENT', 'NOT_OBSERVED']), 'NOT_OBSERVED');
  assert.equal(worstState([]), 'NOT_OBSERVED');
});

test('vacuity guard: the happy-path fixture really does exercise a live control', async () => {
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sourcesContent: ['function o(s){ if(!s.isAdmin) throw 0; return s.ok }'],
  });
  const obs = await observeBundleDir(dir, { witnesses: ['isAdmin'], control: 'function' });
  // If this ever stops being true, every assertion above about REINTRODUCED is
  // passing over a measurement that never happened.
  assert.equal(obs.records[0].controlHeld, true);
  assert.equal(obs.records[0].state, 'REINTRODUCED');
  rmSync(dir, { recursive: true, force: true });
});
