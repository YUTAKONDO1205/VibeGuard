// What the bundle observer must never do is produce a verdict from a blind
// measurement. Most of what follows is that one property, approached from each
// direction a real build can be blind from.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  collectArtefacts,
  sourceMappingUrl,
  readSourceMap,
  observeArtefact,
  observeBundleDir,
  normaliseText,
  CANARY,
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

test('collectArtefacts finds code files and ignores everything else', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  mkdirSync(join(dir, 'nested'));
  writeFileSync(join(dir, 'a.js'), 'export const a = 1;', 'utf8');
  writeFileSync(join(dir, 'nested', 'b.mjs'), 'export const b = 2;', 'utf8');
  writeFileSync(join(dir, 'styles.css'), 'body{}', 'utf8');
  const { artefacts } = await collectArtefacts(dir);
  assert.deepEqual(artefacts.map((a) => a.relPath), ['a.js', 'nested/b.mjs']);
  rmSync(dir, { recursive: true, force: true });
});

test('normaliseText makes a CRLF snippet comparable with an LF source map', () => {
  // Not cosmetic. A finding's snippet comes off a file on disk and a map's
  // sourcesContent comes out of JSON, so on Windows the two routinely differ by
  // exactly this — and every jurisdiction test would fail, silently turning the
  // whole feature into "NOT_OBSERVED for everything".
  assert.equal(normaliseText('a\r\nb'), normaliseText('a\nb'));
});

test('a source map that does not parse yields controlHeld false, never a clean record', async () => {
  const dir = fixture({ code: 'function o(){}', sourcesContent: null, mapText: '{ not json' });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records.length, 1);
  assert.equal(obs.records[0].controlHeld, false);
  assert.match(obs.records[0].why, /did not parse/);
  assert.equal(obs.controlHeld, 0);
  rmSync(dir, { recursive: true, force: true });
});

test('a missing source map is not measurable, and says so', async () => {
  const dir = fixture({ code: 'function o(){}', sourcesContent: [], writeMap: false });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].controlHeld, false);
  assert.match(obs.records[0].why, /no source map/);
  rmSync(dir, { recursive: true, force: true });
});

test('a remote source map is not fetched, and the artefact is not measurable', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  writeFileSync(
    join(dir, 'app.js'),
    'function o(){}\n//# sourceMappingURL=https://cdn.example.com/app.js.map\n',
    'utf8',
  );
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].controlHeld, false);
  assert.match(obs.records[0].why, /no network calls/);
  rmSync(dir, { recursive: true, force: true });
});

test('a map with no sourcesContent is not measurable', async () => {
  // The common real shape: `sourcesRoot` and `sources` present, contents
  // omitted to keep the map small. Nothing can be compared against the original
  // text, so nothing may be concluded.
  const dir = fixture({ code: 'function o(){}', sourcesContent: undefined });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].controlHeld, false);
  assert.match(obs.records[0].why, /no sourcesContent/);
  rmSync(dir, { recursive: true, force: true });
});

test('the NEGATIVE control voids an artefact whose matcher finds what is not there', async () => {
  // If a canary is ever found, the matcher is matching text that does not
  // exist and every verdict from that artefact is worthless. The positive
  // control (per claim, in cross-examine.mjs) and this one bracket the
  // observer from both sides.
  const dir = fixture({
    code: `function o(){} /* ${CANARY} */`,
    sourcesContent: ['function o(){ if(!u.isAdmin) throw 0 }'],
  });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].controlHeld, false);
  assert.match(obs.records[0].why, /negative control matched/);
  assert.equal(obs.records[0].code, null, 'a voided record must not hand its text on');
  rmSync(dir, { recursive: true, force: true });
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

test('a measurable artefact carries both texts, newline-normalised', async () => {
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sourcesContent: ['function o(s){\r\n if(!s.isAdmin) throw 0;\r\n return s.ok\r\n}'],
  });
  const obs = await observeBundleDir(dir);
  const r = obs.records[0];
  assert.equal(r.controlHeld, true);
  assert.ok(r.code.includes('function o(s)'));
  assert.ok(r.sidecar.includes('isAdmin'));
  assert.ok(!r.sidecar.includes('\r'), 'sidecar text must be newline-normalised');
  assert.equal(obs.controlHeld, 1);
  rmSync(dir, { recursive: true, force: true });
});

test('vacuity guard: the happy-path fixture really is measurable', async () => {
  // Without this, every assertion above about controlHeld:false is passing over
  // a fixture set in which nothing was ever measurable.
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sourcesContent: ['function o(s){ if(!s.isAdmin) throw 0; return s.ok }'],
  });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.controlHeld, 1);
  assert.equal(obs.readable, 1);
  rmSync(dir, { recursive: true, force: true });
});

test('an unreadable artefact is reported, not skipped', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  // A directory named like a JS file: collectArtefacts must not admit it, and
  // must not silently drop it either.
  mkdirSync(join(dir, 'weird.js'));
  writeFileSync(join(dir, 'real.js'), 'function o(){}\n', 'utf8');
  const obs = await observeBundleDir(dir);
  assert.deepEqual(obs.records.map((r) => r.artefact), ['real.js']);
  rmSync(dir, { recursive: true, force: true });
});
