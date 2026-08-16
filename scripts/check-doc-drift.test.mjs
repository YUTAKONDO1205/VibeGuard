// scripts/check-doc-drift.test.mjs — vitest（ルート package.json の `test:root`:
// `vitest run --dir scripts` で走る。node:test ではない）。
//
// このテストが守っているのは2方向:
//   ① 嘘を仕込んだ文書に対して**赤くなる**（種入りテスト）
//   ② 正しい文書に対して**赤くならない**（誤検出しない）
// 片方だけだと「常に通る check」か「常に落ちる check」になり、どちらも無価値。
//
// 本物の `docs/実装順（VibeGuardCompiler）.md` は**編集しない**。全て一時コピー。

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  runDriftCheck,
  exitCodeFor,
  parseBlocks,
  extractRepoPaths,
  extractLineRefs,
  extractZeroReaderClaims,
  expandBraces,
  globToRegExp,
  walkTree,
  UNSTARTED_EXPECTATIONS,
  DEFAULT_DOC,
} from './check-doc-drift.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REAL_DOC_ABS = join(REPO_ROOT, DEFAULT_DOC);

let tmpRoot;
const scratch = [];

function newScratch(prefix = 'doc-drift-') {
  const d = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(d);
  return d;
}

/** 最小の「正しい」ツリー＋文書を作る。誤検出テストの基準線。 */
function makeHonestFixture() {
  const root = newScratch();
  mkdirSync(join(root, 'docs'), { recursive: true });
  mkdirSync(join(root, 'compiler', 'driver', 'lib'), { recursive: true });
  mkdirSync(join(root, 'compiler', 'schema'), { recursive: true });
  writeFileSync(join(root, 'compiler', 'driver', 'lib', 'run.mjs'), 'export const a = 1;\nexport const b = 2;\n');
  writeFileSync(
    join(root, 'compiler', 'schema', 'properties.json'),
    JSON.stringify(
      {
        schemaVersion: 'properties-v0',
        extractors: { 'ir.wipe-effect': { component: 'IrCheckpoints', path: 'compiler/driver' } },
        kindCoverage: {
          'must-survive': 'partial -- one extractor, measured at IR only',
          'must-remain-unobservable': 'none -- no extractor, no checkpoint, no measurement',
        },
        properties: [
          {
            id: 'survive.secure-wipe',
            kind: 'must-survive',
            extractor: 'ir.wipe-effect',
            status: 'implemented',
            observeAt: [
              { checkpoint: 'pre-opt-ir', extractor: 'ir.wipe-effect', status: 'implemented', component: 'IrCheckpoints' },
              { checkpoint: 'object', extractor: null, status: 'unimplemented', component: null },
            ],
          },
          {
            id: 'survive.bounds-check',
            kind: 'must-survive',
            extractor: null,
            status: 'unimplemented',
            observeAt: [{ checkpoint: 'object', extractor: null, status: 'unimplemented', component: null }],
          },
          {
            id: 'unobservable.secret-literal',
            kind: 'must-remain-unobservable',
            extractor: null,
            status: 'unimplemented',
            observeAt: [{ checkpoint: 'object', extractor: null, status: 'unimplemented', component: null }],
          },
        ],
      },
      null,
      2,
    ),
  );
  const doc = [
    '# plan',
    '',
    '### #V1. DRV — Driver ✅ 実装済（`compiler/driver/` 1ファイル）',
    '- **実装先**: **`compiler/driver/`**（**`apps/example-driver/` ではない** → 裁定）',
    '- 参照: `compiler/driver/lib/run.mjs:2`',
    '',
    '### #V7. SCE — Security Configuration Envelope ⬜ 未着手',
    '- **何を**: フル包絡',
    '',
  ].join('\n');
  writeFileSync(join(root, 'docs', 'plan.md'), doc);
  return { root, docPath: 'docs/plan.md', docAbs: join(root, 'docs', 'plan.md') };
}

/** 本物の文書を一時ディレクトリにコピーし、`edit` で書き換えたものを返す。 */
function copyRealDocWith(edit) {
  const dir = newScratch('doc-drift-copy-');
  mkdirSync(join(dir, 'docs'), { recursive: true });
  const out = join(dir, 'docs', 'plan.md');
  writeFileSync(out, edit(readFileSync(REAL_DOC_ABS, 'utf8')));
  // 文書だけ差し替え、ツリーは本物を見る（--root は本物のまま）。
  return out;
}

beforeAll(() => {
  tmpRoot = null;
  expect(existsSync(REAL_DOC_ABS), `本物の文書が見つからない: ${REAL_DOC_ABS}`).toBe(true);
});

afterAll(() => {
  for (const d of scratch) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* 掃除の失敗でテストを落とさない */
    }
  }
});

// ── 部品 ──────────────────────────────────────────────────────────────────

describe('部品', () => {
  it('expandBraces が second-language-{record,check,oracle}.mjs を3本に展開する', () => {
    expect(expandBraces('a/second-language-{record,check,oracle}.mjs')).toEqual([
      'a/second-language-record.mjs',
      'a/second-language-check.mjs',
      'a/second-language-oracle.mjs',
    ]);
    expect(expandBraces('plain/path.mjs')).toEqual(['plain/path.mjs']);
  });

  it('globToRegExp: * は / を跨がず、**/ は跨ぐ', () => {
    expect(globToRegExp('compiler/schema/*emit*').test('compiler/schema/emit-observation.mjs')).toBe(true);
    // ここが崩れると `compiler/schema/*emit*` が observation-samples/ の中まで拾い、
    // #V8 の判定が「昔から在ったファイル」で発火してしまう。
    expect(globToRegExp('compiler/schema/*emit*').test('compiler/schema/samples/emit.json')).toBe(false);
    expect(globToRegExp('compiler/**/*fallback*').test('compiler/driver/lib/fallback.mjs')).toBe(true);
    expect(globToRegExp('compiler/**/*fallback*').test('compiler/fallback.mjs')).toBe(true);
    expect(globToRegExp('compiler/**/*fallback*').test('packages/x/fallback.mjs')).toBe(false);
  });

  it('extractRepoPaths が「ではない」の否定文脈を分離する', () => {
    const r = extractRepoPaths('- **実装先**: **`compiler/driver/`**（**`apps/example-driver/` ではない** → 裁定）');
    expect(r.paths).toEqual(['compiler/driver/']);
    expect(r.negated).toEqual(['apps/example-driver/']);
  });

  it('extractRepoPaths がリポジトリ外の実装先（~/… や /tmp/…）を拾わない', () => {
    const r = extractRepoPaths('- **実装先**: `~/outside-tree/scripts/trace.mjs` ／ `/tmp/fixdir`');
    expect(r.paths).toEqual([]);
  });

  it('parseBlocks が ⬜ と ✅/▲ を見出しから判定する', () => {
    const blocks = parseBlocks(
      ['### #V1. DRV — x ✅ 実装済', '本文', '### #V7. SCE — y ⬜ 未着手', '本文', '### #V3. IRCHK — z ▲ 実装済／未達'].join('\n'),
    );
    expect(blocks.map((b) => [b.id, b.status])).toEqual([
      ['#V1', 'CLAIMED_DONE'],
      ['#V7', 'UNSTARTED'],
      ['#V3', 'CLAIMED_DONE'],
    ]);
  });

  it('extractZeroReaderClaims が「`policy.X` の読み手は **0**」を拾う', () => {
    const claims = extractZeroReaderClaims('| 根拠 | `policy.fallback` の読み手は **0**（同じ形の grep が…） |');
    expect(claims).toHaveLength(1);
    expect(claims[0].key).toBe('policy.fallback');
  });

  it('extractLineRefs がリポジトリ相対とベース名だけの参照を分ける', () => {
    const { refs, unresolved } = extractLineRefs('見よ `compiler/driver/lib/run.mjs:105` と `README.md:387`');
    expect(refs).toEqual([{ docLine: 1, path: 'compiler/driver/lib/run.mjs', at: 105 }]);
    expect(unresolved.map((u) => u.path)).toEqual(['README.md']);
  });

  it('walkTree がファイルとディレクトリの両方を返し、node_modules を避ける', () => {
    const root = newScratch();
    mkdirSync(join(root, 'compiler', 'envelope'), { recursive: true });
    mkdirSync(join(root, 'compiler', 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(root, 'compiler', 'envelope', 'fragility.mjs'), '');
    writeFileSync(join(root, 'compiler', 'node_modules', 'x', 'index.js'), '');
    const paths = walkTree(root).map((e) => e.path);
    expect(paths).toContain('compiler/envelope');
    expect(paths).toContain('compiler/envelope/fragility.mjs');
    expect(paths.some((p) => p.includes('node_modules'))).toBe(false);
  });
});

// ── ② 逆向き: 正しい記述に対して誤検出しない ───────────────────────────────

describe('逆向き（誤検出しないこと）', () => {
  it('正しい文書＋正しいツリーでは DRIFT ゼロ・exit 0', () => {
    const { root, docPath } = makeHonestFixture();
    const report = runDriftCheck({ root, docPath });
    expect(report.drifts, JSON.stringify(report.drifts, null, 2)).toEqual([]);
    expect(report.unableToCheck).toEqual([]);
    expect(exitCodeFor(report)).toBe(0);
  });

  it('否定文脈のパスは DRIFT にならず、落としたことが NOTE に出る', () => {
    const { root, docPath } = makeHonestFixture();
    const report = runDriftCheck({ root, docPath });
    expect(report.drifts.filter((d) => d.kind === 'CLAIMED_PATH_MISSING')).toEqual([]);
    expect(report.notes.some((n) => n.kind === 'NEGATED_PATH_SKIPPED' && n.detail.includes('apps/example-driver/'))).toBe(true);
  });

  it('⬜ ブロックは、期待成果物が実在しなければ黙って通る', () => {
    const { root, docPath } = makeHonestFixture();
    const report = runDriftCheck({ root, docPath });
    expect(report.drifts.filter((d) => d.check === '2')).toEqual([]);
    // ただし「検査した」ことは数えられていなければならない（空振りは clean ではない）。
    expect(report.counters.unstartedBlocksProbed).toBeGreaterThan(0);
  });

  it('本物のツリーに対して検査 [1]（✅ が主張するパス）は現状きれい', () => {
    const report = runDriftCheck({ root: REPO_ROOT, docPath: DEFAULT_DOC });
    expect(report.drifts.filter((d) => d.check === '1'), JSON.stringify(report.drifts.filter((d) => d.check === '1'), null, 2)).toEqual([]);
    expect(report.counters.pathClaimsChecked).toBeGreaterThan(20);
    expect(report.counters.lineRefsChecked).toBeGreaterThan(10);
  });
});

// ── ① 種入りの嘘に対して赤くなる ──────────────────────────────────────────

describe('種入りの嘘（seeded lie）', () => {
  it('偽の「✅ 実装済（`compiler/存在しない.mjs`）」を検出する', () => {
    const doc = copyRealDocWith(
      (t) => t + '\n\n### #V99. FAKE — でっちあげブロック ✅ 実装済（`compiler/存在しない.mjs`）\n- **何を**: 何も\n',
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: doc });
    const hit = report.drifts.filter((d) => d.kind === 'CLAIMED_PATH_MISSING');
    expect(hit).toHaveLength(1);
    expect(hit[0].block).toBe('#V99');
    expect(hit[0].detail).toContain('compiler/存在しない.mjs');
    expect(exitCodeFor(report)).toBe(1);
  });

  it('偽の実装先バレット（`- **実装先**: `packages/存在しない/``）を検出する', () => {
    const doc = copyRealDocWith(
      (t) => t + '\n\n### #V98. FAKE2 — でっちあげ ▲ 実装済\n- **実装先**: `packages/存在しない-package/`\n',
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: doc });
    expect(
      report.drifts.some((d) => d.kind === 'CLAIMED_PATH_MISSING' && d.detail.includes('packages/存在しない-package/')),
    ).toBe(true);
  });

  it('存在するファイルの存在しない行への参照を検出する', () => {
    const doc = copyRealDocWith((t) => t + '\n\n根拠は `compiler/driver/lib/run.mjs:999999` にある。\n');
    const report = runDriftCheck({ root: REPO_ROOT, docPath: doc });
    const hit = report.drifts.filter((d) => d.kind === 'LINEREF_OUT_OF_RANGE');
    expect(hit).toHaveLength(1);
    expect(hit[0].detail).toContain('compiler/driver/lib/run.mjs:999999');
  });

  it('存在しないファイルへの path:line 参照を検出する', () => {
    const doc = copyRealDocWith((t) => t + '\n\n根拠は `compiler/nowhere/none.mjs:1` にある。\n');
    const report = runDriftCheck({ root: REPO_ROOT, docPath: doc });
    expect(report.drifts.some((d) => d.kind === 'LINEREF_FILE_MISSING')).toBe(true);
  });

  it('「✅ を ⬜ に戻す」嘘 ── 実装済みのものを未着手と書き直すと [2] が鳴る', () => {
    // #V1 DRV は `compiler/driver/` が実在する。見出しを ⬜ に書き換え、
    // 実装先バレットはそのまま残す（＝文書内で完結した矛盾）。
    const doc = copyRealDocWith((t) =>
      t.replace(
        /^### #V1\. DRV — .*$/m,
        '### #V1. DRV — Driver ブロック（PLAN §20 v0.1）⬜ 未着手',
      ),
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: doc });
    const hit = report.drifts.filter((d) => d.check === '2' && d.block === '#V1');
    expect(hit, JSON.stringify(report.drifts.filter((d) => d.check === '2'), null, 2)).toHaveLength(1);
    expect(hit[0].kind).toBe('UNSTARTED_BUT_ARTEFACT_EXISTS');
    expect(hit[0].hits).toContain('compiler/driver/');
  });
});

// ── ★ 出生時陽性対照（合成版・本物の文書の将来の書き換えに依存しない） ──────

describe('★ 出生時陽性対照（合成）', () => {
  it('「#V10 ⬜ 未着手」だけを書いた文書 × 本物のツリー → fallback.mjs で FLAG される', () => {
    const dir = newScratch('doc-drift-pc-');
    mkdirSync(join(dir, 'docs'), { recursive: true });
    writeFileSync(
      join(dir, 'docs', 'plan.md'),
      [
        '### #V1. DRV — Driver ✅ 実装済（`compiler/driver/`）',
        '- **実装先**: `compiler/driver/`',
        '',
        '### #V10. FBACK — Security-Preserving Fallback（PLAN §4.7）⬜ 未着手',
        '- **何を**: 性質が失われた関数だけを再コンパイルする',
        '',
      ].join('\n'),
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: join(dir, 'docs', 'plan.md') });
    const hit = report.drifts.find((d) => d.check === '2' && d.block === '#V10');
    expect(hit, '#V10 が FLAG されなかった＝検出器が何も検査していない').toBeTruthy();
    expect(hit.hits.some((p) => p.endsWith('fallback.mjs'))).toBe(true);
  });

  it('「#V8 ⬜ 未着手」× 本物のツリー → observation schema の書き手で FLAG される', () => {
    const dir = newScratch('doc-drift-pc8-');
    mkdirSync(join(dir, 'docs'), { recursive: true });
    writeFileSync(
      join(dir, 'docs', 'plan.md'),
      [
        '### #V1. DRV — Driver ✅ 実装済（`compiler/driver/`）',
        '- **実装先**: `compiler/driver/`',
        '',
        '### #V8. BEYOND — Beyond 統合（PLAN §20 v0.8）⬜ 未着手【縮小】',
        '- **何を**: Observation Schema への出力形の定義まで',
        '',
      ].join('\n'),
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: join(dir, 'docs', 'plan.md') });
    const hit = report.drifts.find((d) => d.check === '2' && d.block === '#V8');
    expect(hit, '#V8 が FLAG されなかった＝検出器が何も検査していない').toBeTruthy();
    expect(hit.hits.some((p) => p.includes('emit-observation'))).toBe(true);
  });

  it('「`policy.fallback` の読み手は 0」という文書の自称は、いま偽である', () => {
    const dir = newScratch('doc-drift-zero-');
    mkdirSync(join(dir, 'docs'), { recursive: true });
    writeFileSync(
      join(dir, 'docs', 'plan.md'),
      [
        '### #V1. DRV — Driver ✅ 実装済（`compiler/driver/`）',
        '- **実装先**: `compiler/driver/`',
        '',
        '| #V10 | ⬜ 未着手 | 未着手（真） | `policy.fallback` の読み手は **0** |',
        '',
      ].join('\n'),
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: join(dir, 'docs', 'plan.md') });
    const hit = report.drifts.find((d) => d.kind === 'ZERO_READER_CLAIM_FALSIFIED');
    expect(hit, '「読み手 0」の主張を再実行できていない').toBeTruthy();
    expect(hit.hits).toContain('compiler/driver/lib/fallback.mjs');
  });
});

// ── ★ 出生時陽性対照（本物の文書。将来 ✅ に直されたら条件が外れる） ─────────

describe('★ 出生時陽性対照（本物の docs/実装順（VibeGuardCompiler）.md）', () => {
  const realDoc = () => readFileSync(REAL_DOC_ABS, 'utf8');
  const isUnstarted = (id) => {
    const b = parseBlocks(realDoc()).find((x) => x.id === id);
    return Boolean(b && b.status === 'UNSTARTED');
  };

  for (const id of ['#V8', '#V10']) {
    it(`${id} が ⬜ のままである限り、本物のツリーに対して FLAG される`, () => {
      const report = runDriftCheck({ root: REPO_ROOT, docPath: DEFAULT_DOC });
      if (!isUnstarted(id)) {
        // 文書が直されたなら、FLAG が消えていることが正しい状態。
        expect(report.drifts.some((d) => d.check === '2' && d.block === id)).toBe(false);
        return;
      }
      const hit = report.drifts.find((d) => d.check === '2' && d.block === id);
      expect(hit, `${id} は ⬜ 未着手のままなのに FLAG されていない`).toBeTruthy();
      expect(hit.hits.length).toBeGreaterThan(0);
    });
  }
});

// ── 対応不明を黙って外していないこと ─────────────────────────────────────

describe('対応不明の明示', () => {
  it('期待成果物を定義できない ⬜ ブロックは unmapped に載る（黙って検査対象外にしない）', () => {
    const dir = newScratch('doc-drift-unmapped-');
    mkdirSync(join(dir, 'docs'), { recursive: true });
    writeFileSync(
      join(dir, 'docs', 'plan.md'),
      [
        '### #V1. DRV — Driver ✅ 実装済（`compiler/driver/`）',
        '- **実装先**: `compiler/driver/`',
        '',
        '### #V7. SCE — Envelope ⬜ 未着手',
        '- **何を**: フル包絡',
        '',
        '### #V42. NOMAP — 表にも実装先にも無いブロック ⬜ 未着手',
        '- **何を**: 未知',
        '',
      ].join('\n'),
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: join(dir, 'docs', 'plan.md') });
    expect(report.unmapped.map((u) => u.block)).toContain('#V42');
    // #V7 は名前規約表にあるので unmapped ではない
    expect(report.unmapped.map((u) => u.block)).not.toContain('#V7');
  });

  it('UNSTARTED_EXPECTATIONS の全項目に basis（根拠の出典）が書かれている', () => {
    for (const e of UNSTARTED_EXPECTATIONS) {
      expect(e.basis, `${e.id} に basis が無い`).toBeTruthy();
      expect(e.basis.length).toBeGreaterThan(20);
    }
  });
});

// ── 「検査が走らなかった」を clean と区別すること ───────────────────────────

describe('静かな exit 0 を作らない', () => {
  it('文書が無ければ exit 3（0 ではない）', () => {
    const report = runDriftCheck({ root: REPO_ROOT, docPath: 'docs/no-such-plan.md' });
    expect(report.unableToCheck.length).toBeGreaterThan(0);
    expect(exitCodeFor(report)).toBe(3);
  });

  it('ブロックが1つも解析できない文書は exit 3', () => {
    const dir = newScratch('doc-drift-empty-');
    mkdirSync(join(dir, 'docs'), { recursive: true });
    writeFileSync(join(dir, 'docs', 'plan.md'), '# 見出しだけ\n本文に ### #V1. の形が無い\n');
    const report = runDriftCheck({ root: REPO_ROOT, docPath: join(dir, 'docs', 'plan.md') });
    // 文書由来の検査 [1][2] は1本も走っていない。それを DRIFT ゼロ＝clean と
    // 読ませないために unableToCheck が立つ（[3] は独立に走るので残ってよい）。
    expect(report.drifts.filter((d) => d.check !== '3')).toEqual([]);
    expect(report.unableToCheck.length).toBeGreaterThan(0);
    expect(exitCodeFor(report)).toBe(3);
  });

  it('⬜ ブロックがあるのに1本も検査できなければ exit 3', () => {
    const dir = newScratch('doc-drift-noprobe-');
    mkdirSync(join(dir, 'docs'), { recursive: true });
    writeFileSync(
      join(dir, 'docs', 'plan.md'),
      [
        '### #V1. DRV — Driver ✅ 実装済（`compiler/driver/`）',
        '- **実装先**: `compiler/driver/`',
        '',
        '### #V42. NOMAP — 対応不明 ⬜ 未着手',
        '',
      ].join('\n'),
    );
    const report = runDriftCheck({ root: REPO_ROOT, docPath: join(dir, 'docs', 'plan.md') });
    expect(exitCodeFor(report)).toBe(3);
    expect(report.unableToCheck.join('\n')).toContain('検査 [2] は空振り');
  });
});

// ── 検査 [3] properties.json ───────────────────────────────────────────────

describe('検査 [3] properties.json の内部整合', () => {
  function withProperties(mutate) {
    const { root, docPath } = makeHonestFixture();
    const p = join(root, 'compiler', 'schema', 'properties.json');
    const cat = JSON.parse(readFileSync(p, 'utf8'));
    mutate(cat);
    writeFileSync(p, JSON.stringify(cat, null, 2));
    return runDriftCheck({ root, docPath });
  }

  it('status=implemented なのに extractor が null なら鳴る', () => {
    const r = withProperties((c) => {
      c.properties[0].extractor = null;
    });
    expect(r.drifts.some((d) => d.kind === 'IMPLEMENTED_WITHOUT_EXTRACTOR')).toBe(true);
  });

  it('未知の extractor を指していれば鳴る', () => {
    const r = withProperties((c) => {
      c.properties[0].extractor = 'ir.does-not-exist';
    });
    expect(r.drifts.some((d) => d.kind === 'UNKNOWN_EXTRACTOR')).toBe(true);
  });

  it('checkpoint 側が implemented なのに property 側がそうでなければ鳴る', () => {
    const r = withProperties((c) => {
      c.properties[0].status = 'partial';
    });
    expect(r.drifts.some((d) => d.kind === 'KIND_VS_CHECKPOINT_MISMATCH')).toBe(true);
  });

  it('kindCoverage が "none" なのに実装済み entry があれば鳴る', () => {
    const r = withProperties((c) => {
      c.kindCoverage['must-survive'] = 'none -- 何も無い';
    });
    expect(r.drifts.some((d) => d.kind === 'COVERAGE_SAYS_NONE_BUT_ENTRIES_DISAGREE')).toBe(true);
  });

  it('kindCoverage が "partial" なのに全 entry が implemented なら鳴る', () => {
    const r = withProperties((c) => {
      c.properties = c.properties.filter((p) => p.kind !== 'must-survive' || p.status === 'implemented');
    });
    expect(r.drifts.some((d) => d.kind === 'COVERAGE_SAYS_PARTIAL_BUT_ALL_IMPLEMENTED')).toBe(true);
  });

  it('extractor の path が存在しなければ鳴る', () => {
    const r = withProperties((c) => {
      c.extractors['ir.wipe-effect'].path = 'compiler/no-such-component';
    });
    expect(r.drifts.some((d) => d.kind === 'EXTRACTOR_PATH_MISSING')).toBe(true);
  });

  it('properties.json が壊れていれば「検査が走らなかった」になる（clean にしない）', () => {
    const { root, docPath } = makeHonestFixture();
    writeFileSync(join(root, 'compiler', 'schema', 'properties.json'), '{ not json');
    const r = runDriftCheck({ root, docPath });
    expect(r.unableToCheck.some((u) => u.includes('JSON'))).toBe(true);
    expect(exitCodeFor(r)).toBe(3);
  });

  it('本物の properties.json は「24件・implemented 5」であり、検査 [3] は実際に走っている', () => {
    const report = runDriftCheck({ root: REPO_ROOT, docPath: DEFAULT_DOC });
    expect(report.counters.propertiesChecked).toBe(24);
  });
});
