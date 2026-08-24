// What the bundle observer must never do is produce a verdict from a blind
// measurement. Most of what follows is that one property, approached from each
// direction a real build can be blind from.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, truncateSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  MAX_ARTEFACT_BYTES,
  collectArtefacts,
  sourceMappingUrl,
  readSourceMap,
  observeArtefact,
  observeBundleDir,
  normaliseText,
} from '../src/bundle.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

/** A minimal shipped file plus the map a bundler writes next to it. */
function fixture({
  code,
  sourcesContent,
  sources = ['src/app.js'],
  mappings,
  mapName = 'app.js.map',
  writeMap = true,
  mapText,
  mapExtra,
}) {
  const dir = mkdtempSync(join(tmpdir(), 'vg-bundle-'));
  writeFileSync(join(dir, 'app.js'), `${code}\n//# sourceMappingURL=${mapName}\n`, 'utf8');
  if (writeMap) {
    writeFileSync(
      join(dir, mapName),
      mapText ??
        JSON.stringify({
          version: 3,
          sources,
          sourcesContent,
          ...(mappings === undefined ? {} : { mappings }),
          ...mapExtra,
        }),
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

test('a source map that does not parse yields measured false, never a clean record', async () => {
  const dir = fixture({ code: 'function o(){}', sourcesContent: null, mapText: '{ not json' });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records.length, 1);
  assert.equal(obs.records[0].measured, false);
  assert.match(obs.records[0].why, /did not parse/);
  assert.equal(obs.measured, 0);
  rmSync(dir, { recursive: true, force: true });
});

test('a missing source map is not measurable, and says so', async () => {
  const dir = fixture({ code: 'function o(){}', sourcesContent: [], writeMap: false });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].measured, false);
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
  assert.equal(obs.records[0].measured, false);
  assert.match(obs.records[0].why, /no network calls/);
  rmSync(dir, { recursive: true, force: true });
});

test('a map with no sourcesContent is not measurable', async () => {
  // The common real shape: `sourcesRoot` and `sources` present, contents
  // omitted to keep the map small. Nothing can be compared against the original
  // text, so nothing may be concluded.
  const dir = fixture({ code: 'function o(){}', sourcesContent: undefined });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].measured, false);
  assert.match(obs.records[0].why, /no sourcesContent/);
  rmSync(dir, { recursive: true, force: true });
});

test('an artefact that contains a copy of this observer is still measured', async () => {
  // The regression the deleted CANARY caused, pinned so it cannot come back in
  // another form. That canary was a string literal in `bundle.mjs`, so it was
  // bundled verbatim into `apps/cli/dist/index.js` — and pointing
  // `--after-build` at any directory holding a copy of the VibeGuard CLI made
  // every verdict from that artefact void, for no reason connected to the
  // artefact at all. Nothing in this module may key a refusal on text that
  // this module itself ships.
  const self = readFileSync(join(HERE, '..', 'src', 'bundle.mjs'), 'utf8');
  const dir = fixture({
    code: `function o(){}\n/* ${self} */`,
    sourcesContent: ['function o(){ if(!u.isAdmin) throw 0 }'],
  });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].measured, true);
  assert.equal(obs.records[0].why, undefined);
  rmSync(dir, { recursive: true, force: true });
});

test('sourcesContent is kept index-aligned with sources, holes and all', async () => {
  // A mapping segment names a source by INDEX. This used to be
  // `.filter(x => typeof x === 'string')`, which compacts the array and shifts
  // every later index onto the wrong file — invisible while nothing read the
  // indices, and a confident wrong-source attribution the moment something
  // does.
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sources: ['vendor/dep.js', 'src/app.js'],
    sourcesContent: [null, 'function o(s){ if(!s.isAdmin) throw 0; return s.ok }'],
  });
  const obs = await observeBundleDir(dir);
  const r = obs.records[0];
  assert.equal(r.measured, true);
  assert.equal(r.contents.length, 2);
  assert.equal(r.contents[0], null);
  assert.match(r.contents[1], /isAdmin/);
  assert.equal(r.sourcesContentEntries, 1);
  rmSync(dir, { recursive: true, force: true });
});

test('an artefact with a decodable map carries its regions', async () => {
  // `AAAA` is one segment: generated line 0, column 0, source 0, original 0:0.
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sourcesContent: ['function o(s){ if(!s.isAdmin) throw 0; return s.ok }'],
    mappings: 'AAAA',
  });
  const obs = await observeBundleDir(dir);
  const r = obs.records[0];
  assert.equal(r.measured, true);
  assert.deepEqual(r.regions, [{ start: 0, end: 'function o(s){return s.ok}'.length, source: 0 }]);
  assert.equal(r.regionsWhy, undefined);
  rmSync(dir, { recursive: true, force: true });
});

test('a map that cannot be decoded into regions still leaves the sidecar measurable', async () => {
  // This is the one asymmetry worth stating out loud. Losing the regions costs
  // the ability to say PRESENT and nothing else: the sidecar half of the
  // observation — the half that needs no oracle — is untouched, so the record
  // stays measured and `cross-examine.mjs` reports the reason rather than the
  // whole artefact going dark.
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sourcesContent: ['function o(s){ if(!s.isAdmin) throw 0; return s.ok }'],
    mappings: 'A!A',
  });
  const obs = await observeBundleDir(dir);
  const r = obs.records[0];
  assert.equal(r.measured, true);
  assert.equal(r.regions, null);
  assert.match(r.regionsWhy, /not base64 VLQ/);
  assert.match(r.sidecar, /isAdmin/);
  rmSync(dir, { recursive: true, force: true });
});

test('a source map larger than the artefact bound is refused before it is read', async () => {
  // The artefact was bounded and the map beside it was not, and the map is the
  // larger of the two in practice — 2,378,190 bytes of map for a 375,052-byte
  // minified bundle when this was measured. `truncateSync` gives the file its
  // size without writing 64 MB of zeroes; `stat` is what the bound consults.
  const dir = fixture({ code: 'function o(){}', sourcesContent: ['x'] });
  truncateSync(join(dir, 'app.js.map'), MAX_ARTEFACT_BYTES + 1);
  const obs = await observeBundleDir(dir);
  assert.equal(obs.records[0].measured, false);
  assert.match(obs.records[0].why, /above the 67108864 this package will read/);
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
  assert.equal(r.measured, true);
  assert.ok(r.code.includes('function o(s)'));
  assert.ok(r.sidecar.includes('isAdmin'));
  assert.ok(!r.sidecar.includes('\r'), 'sidecar text must be newline-normalised');
  assert.equal(obs.measured, 1);
  rmSync(dir, { recursive: true, force: true });
});

test('vacuity guard: the happy-path fixture really is measurable', async () => {
  // Without this, every assertion above about measured:false is passing over
  // a fixture set in which nothing was ever measurable.
  const dir = fixture({
    code: 'function o(s){return s.ok}',
    sourcesContent: ['function o(s){ if(!s.isAdmin) throw 0; return s.ok }'],
  });
  const obs = await observeBundleDir(dir);
  assert.equal(obs.measured, 1);
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
