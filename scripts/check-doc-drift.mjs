#!/usr/bin/env node
// check-doc-drift — 計画文書と実ツリーの食い違いを機械で見つける。
//
//   npm run check:docs
//   node scripts/check-doc-drift.mjs --json
//   node scripts/check-doc-drift.mjs --doc <別の md> --root <別のツリー>
//
// ⚠ CI に置くな。**恒久的に赤になる。**
//
// この検査のオラクルは計画文書だが、その文書は `.gitignore:71`（`docs/*.md`）で
// 意図的に追跡対象外 ── つまり CI のチェックアウトには存在しない。文書が無いとき
// この検査は exit 3（検査を完了できなかった）を返す。これは正しい振る舞いであって、
// 「対象ゼロなので成功」と言わないための設計だが、CI では毎ラン赤になる。
// 赤の原因が欠陥ではなく設計なら、その赤は数週間で無視されるようになり、
// 本物の赤も一緒に無視される。だから**ゲートにせず、手で走らせる入口として置く**。
// 走らせる相手は、この文書を実際に持っている人間とエージェント。
//
// 文書を追跡対象にすればゲートにできる。だがその判断は公開衛生の裁定であって、
// この検査が単独で決めてよいことではない（文書は計画ラベルと会場名を含む）。
//
// WHY THIS FILE EXISTS
//
// このリポジトリでは「実装は終わっていた。腐っていたのは文書」が繰り返し起きている。
// 直近では #V5 / #V5b / #V6 / #V11 / #V12 / #V13 の6ブロックが「⬜ 未着手」と書かれた
// まま既に origin/main に載っており、人間の全数監査で初めて見つかった。文書が
// 「まだやっていない」と言い続ける限り、実装済みのものが二度実装され、原稿には
// 「未実装」と書かれる。これを人間の目ではなく終了コードで捕まえるのがこの検査。
//
// THE ASYMMETRY THIS FILE IS BUILT AROUND
//
// 「✅ が嘘」は読めば分かる（パスを開けば無い）。**「⬜ が嘘」は読んでも分からない**
// ── 存在しないはずのものを探しに行く人がいないから。だから検査 [2] が本体で、
// [1] と [3] はその足場である。
//
// HONEST SCOPE — 名乗らないことを先に書く
//
//   * 検査 [1][2] は `### #C… / #V…` 見出しで始まるブロックだけを見る。
//     地の文（§2.x の監査記録など）の主張は [1c] の `path:line` 参照しか見ない。
//   * ⬜ ブロックの「期待成果物」は、文書が `- **実装先**:` を書いていれば
//     そこから取る。書いていなければ UNSTARTED_EXPECTATIONS の名前規約から
//     取り、それも無いものは「対応不明」として報告に出す（黙って外さない）。
//   * この検査はファイルの**存在**しか見ない。存在するものが**動く**かは見ない。
//
// EXIT CODES — 「静かな exit 0」を作らないための規律
//
//   0  全検査が走り、DRIFT ゼロ
//   1  DRIFT あり
//   2  使い方の誤り／内部エラー
//   3  **検査が走らなかった** — 文書が読めない、ブロックが1つも解析できない、
//      期待パスが1本も抽出できない等。「何も検査しなかった run」は clean ではない。
//
// 検査結果は必ず「何本の主張を検査したか」を併記する。0本検査して DRIFT 0 は
// clean ではなく exit 3 である。

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, sep } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_ROOT = resolve(HERE, '..');
export const DEFAULT_DOC = 'docs/実装順（VibeGuardCompiler）.md';

// リポジトリ相対とみなす先頭セグメント。`~/<作業領域>/…` や `/tmp/…` や
// `Ubuntu-24.04` のような「リポジトリ外の実装先」をここで落とす。一部のブロックは
// 実装先が丸ごとリポジトリ外なので、この足切りが無いと検査 [1] は全滅する。
// 許可リストであって禁止リストではない ── 具体的な作業領域名をここに書くと、
// この検査自身が scripts/sweep-disclosure.mjs と pre-push の語彙ガードの
// 対象になる。形で落とせるものを名前で落とさない。
const REPO_ROOTS = [
  'compiler/',
  'packages/',
  'apps/',
  'extensions/',
  'scripts/',
  'samples/',
  'docs/',
  '.github/',
];

const WALK_SKIP = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'coverage',
  '_results',
  '_store',
  '.vscode-test',
  '.next',
]);

// ── ⬜ 未着手ブロックの期待成果物 ───────────────────────────────────────────
//
// 文書が `- **実装先**:` を書いていないブロックのための表。**各行に basis
// （どの記述から取ったか）を必ず書く。** basis の無い行を足さないこと ── それは
// 「答えを見てから書いた表」であって検査ではない。
//
// glob は「そのブロックが着手されたら、この名前のものが生えるはず」という
// 名前規約であって、実在ファイル名の転記ではない。実際、ここに並ぶ glob は
// `git ls-tree -r HEAD` 時点の compiler/ + packages/ に対して**1本も当たらない**
// （2026-08-16 実測）。当たり始めたことが drift の信号になる。
export const UNSTARTED_EXPECTATIONS = [
  {
    id: '#V7',
    basis:
      '§2.14(c) 表「構成包絡の実装は無い。`llvm-pass/scripts/run-matrix.sh` ＋ `check-matrix.py` が骨格として在るだけ」／本文「フル包絡（-O0〜-O3 / NDEBUG / LTO / target 差）＋ Fragility Score」',
    globs: [
      'compiler/**/*envelope*',
      'compiler/**/*fragility*',
      'packages/**/*envelope*',
      'packages/**/*fragility*',
    ],
  },
  {
    id: '#V8',
    basis:
      '本文「**Observation Schema への出力形の定義まで**に縮小する」＋ DoD「v0.8（#V8）: Observation Schema への出力形が定義され、スキーマ検証が通る」＝ observation.schema.json の**書き手**が生える',
    globs: [
      'compiler/schema/*emit*',
      'compiler/schema/*writ*',
      'compiler/schema/*produce*',
      // `*gen*` stood here and was removed on 2026-08-16. It is three characters
      // inside a substring match, so it fired on le-gen-d, a-gen-t, oxy-gen and
      // re-gen-erate -- and it did NOT match `emit-observation.mjs`, the one file
      // #V8 actually grew. Zero true positives, three demonstrated false ones. A
      // name convention that cannot hit its own subject is not evidence of drift;
      // it is a second thing to audit. `*generat*` was considered and rejected for
      // the same reason `*emit*` already covers the case.
    ],
  },
  {
    id: '#V9',
    basis:
      '本文「Unit Fixtures / Mutation Fixtures / **Negative Controls** ／ OSS 評価 ／ アブレーション A–I ／ 再現パッケージ」',
    globs: [
      'compiler/**/*ablation*',
      'compiler/**/*negative-control*',
      'compiler/**/*oss-eval*',
      'compiler/**/*research-release*',
    ],
  },
  {
    id: '#V10',
    basis:
      '見出し「FBACK — Security-Preserving Fallback」＋ §2.14(c)「#V10 は陽性対照つきで確定 ── `policy.fallback` の読み手は **0**」',
    globs: ['compiler/**/*fallback*', 'packages/**/*fallback*'],
  },
  {
    id: '#C8',
    basis:
      // 会場名も計画ラベルも書かない。ここは「なぜ成果物が生えないと期待するか」を
      // 述べる欄であって、どの原稿かを述べる欄ではない。scripts/sweep-disclosure.mjs
      // が両方を開示形状として拾うので、書けば tracked tree の findings になる。
      '執筆ブロック。成果物は原稿であってリポジトリ内のファイルではなく、実装先もリポジトリ外（§0）',
    globs: [], // → 対応不明として報告される
    outOfRepo: true,
  },
];

// ── 小道具 ────────────────────────────────────────────────────────────────

const isRepoRelative = (p) => REPO_ROOTS.some((r) => p.startsWith(r));

/** `a/{x,y}/b.mjs` → ['a/x/b.mjs', 'a/y/b.mjs']。入れ子は展開しない（文書に無い）。 */
export function expandBraces(spec) {
  const m = /\{([^{}]*)\}/.exec(spec);
  if (!m) return [spec];
  const out = [];
  for (const alt of m[1].split(',')) {
    out.push(...expandBraces(spec.slice(0, m.index) + alt.trim() + spec.slice(m.index + m[0].length)));
  }
  return out;
}

/** `**` はセパレータを跨ぐ、`*` は跨がない。 */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**/` は「0個以上のディレクトリ」を意味させる
        if (glob[i + 2] === '/') {
          re += '(?:[^/]*/)*';
          i += 2;
        } else {
          re += '.*';
          i += 1;
        }
      } else re += '[^/]*';
    } else if ('.+?^${}()|[]\\'.includes(c)) re += '\\' + c;
    else re += c;
  }
  return new RegExp('^' + re + '$', 'i');
}

/** ツリー内の全エントリ（ファイルとディレクトリ）をリポジトリ相対 posix パスで返す。 */
export function walkTree(root, subdirs = ['compiler', 'packages']) {
  const out = [];
  const visit = (abs, rel) => {
    let entries;
    try {
      entries = readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (WALK_SKIP.has(e.name)) continue;
      const childRel = rel ? rel + '/' + e.name : e.name;
      if (e.isDirectory()) {
        out.push({ path: childRel, dir: true });
        visit(join(abs, e.name), childRel);
      } else if (e.isFile()) {
        out.push({ path: childRel, dir: false });
      }
    }
  };
  for (const d of subdirs) {
    const abs = join(root, d);
    if (existsSync(abs)) visit(abs, d);
  }
  return out;
}

const isTestPath = (p) => /(^|\/)(test|tests|__tests__)\//.test(p) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(p);

// Prose about a block is not the block. Only the name-convention globs consult
// this -- a path the document itself declares as `- **実装先**:` is checked as
// written, whatever its extension.
const isProsePath = (p) => /\.(md|markdown|txt|rst|adoc)$/i.test(p) || /(^|\/)docs?\//.test(p);

// ── 文書の解析 ────────────────────────────────────────────────────────────

/** `### #V10. FBACK — … ⬜ 未着手【…】` を1ブロックとして切り出す。 */
export function parseBlocks(docText) {
  const lines = docText.split(/\r?\n/);
  const headRe = /^###\s+(#(?:C|V)\d+[a-z]?(?:-[A-Za-z]+)?)\.\s/;
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const m = headRe.exec(lines[i]);
    if (!m) continue;
    blocks.push({ id: m[1], line: i + 1, heading: lines[i] });
  }
  for (let i = 0; i < blocks.length; i++) {
    const endLine = i + 1 < blocks.length ? blocks[i + 1].line - 1 : lines.length;
    const b = blocks[i];
    b.body = lines.slice(b.line - 1, endLine).join('\n');
    // 見出しのマーカー。⬜ が最優先（「▲ …／⬜ …」のような混在は無いが、
    // 混ざったら未着手側に倒して過検出する ── 見落とすより鳴らす）。
    b.status = b.heading.includes('⬜')
      ? 'UNSTARTED'
      : /✅|▲/.test(b.heading)
        ? 'CLAIMED_DONE'
        : 'UNMARKED';
    const impl = /^-\s+\*\*実装先\*\*:\s*(.*)$/m.exec(b.body);
    b.implLine = impl ? impl[1] : null;
  }
  return blocks;
}

// 「`apps/<名前>/` ではない」のように、**存在しないことを述べている**パス。
// これを実在主張として数えると、正しい記述に対して誤検出する（実例が #V1 にある）。
const NEGATION_AFTER = /^\s*(?:\*\*)?\s*(?:では(?:ない|なく)|じゃない|は無い|ではありません)/;

/**
 * 1行からバッククォート付きのリポジトリ相対パスを取り出す（brace 展開込み）。
 * 否定文脈のものは `negated` に分け、落とした事実を呼び出し側に返す（黙って捨てない）。
 *
 * @returns {{ paths: string[], negated: string[] }}
 */
export function extractRepoPaths(line) {
  const paths = [];
  const negated = [];
  if (!line) return { paths, negated };
  for (const m of line.matchAll(/`([^`\n]+)`/g)) {
    const raw = m[1].trim();
    if (/\s/.test(raw) && !raw.includes('{')) continue; // `git check-ignore -v …` のようなコマンド行
    const after = line.slice(m.index + m[0].length, m.index + m[0].length + 24);
    const isNegated = NEGATION_AFTER.test(after);
    for (const one of expandBraces(raw)) {
      const p = one.replace(/^\.\//, '');
      if (!isRepoRelative(p)) continue;
      (isNegated ? negated : paths).push(p);
    }
  }
  return { paths, negated };
}

/** 文書全体の `path:line` 参照（リポジトリ相対のもの）。 */
export function extractLineRefs(docText) {
  const lines = docText.split(/\r?\n/);
  const re = /`([A-Za-z0-9_.\-/]+\.(?:mjs|cjs|js|ts|tsx|json|md|sh|py|cpp|hpp|h|yml|yaml)):(\d+)(?:-\d+)?`/g;
  const refs = [];
  const unresolved = [];
  for (let i = 0; i < lines.length; i++) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(lines[i]))) {
      const rec = { docLine: i + 1, path: m[1], at: Number(m[2]) };
      if (isRepoRelative(m[1])) refs.push(rec);
      else unresolved.push(rec);
    }
  }
  return { refs, unresolved };
}

/** §2.14(c) 型の「`policy.X` の読み手は **0**」を、文書が自分で出した検査可能な主張として拾う。 */
// 打ち消し線 `~~…~~` の中にある主張は、文書が**自分で撤回した**主張であって、
// 現に述べている主張ではない。この区別が無いと、この検査は撤回を認識できず、
// 満たす唯一の方法が「履歴の行ごと削除」になる ── それはこの文書が §2.13(e) 以来
// 守っている「消さずに訂正を併記する」規約と正面から衝突する。
// 検査が、記録を消すことでしか黙らないなら、その検査は記録を敵に回している。
const STRUCK_THROUGH = /~~[^~]*~~/g;

// 撤回の明示。打ち消し線を付けずに散文で「これは偽になった」と書く形も同じ扱いにする。
// 活用語尾ではなく語幹で拾う ── 「偽になった」だけを見ていたので「偽になっていること」を
// 取りこぼし、撤回を報告している文自身が撤回されていない主張として鳴った（2026-08-16 実測）。
// 撤回の言い回しを網羅しようとするのは負ける勝負なので、語幹＋打ち消し線の二本立てにしてある。
const RETRACTION_NEARBY = /(偽になっ|もはや真ではな|真でなくなっ|この記述は誤り|訂正|反証)/;

export function extractZeroReaderClaims(docText) {
  const lines = docText.split(/\r?\n/);
  const re = /`(policy\.[A-Za-z0-9_.]+)`\s*の読み手は\s*\*{0,2}0\*{0,2}/g;
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    // 撤回済みの引用を落としてから走査する。行の残りに主張が残っていれば、
    // それは撤回されていない主張なので、従来どおり検査対象。
    const live = lines[i].replace(STRUCK_THROUGH, '');
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(live))) {
      // 同じ行が撤回を明言しているなら、それは主張ではなく主張への言及。
      if (RETRACTION_NEARBY.test(lines[i])) continue;
      out.push({ docLine: i + 1, key: m[1] });
    }
  }
  return out;
}

// ── 検査本体 ──────────────────────────────────────────────────────────────

export function runDriftCheck({ root = DEFAULT_ROOT, docPath = DEFAULT_DOC } = {}) {
  const drifts = [];
  const notes = [];
  const unmapped = [];
  const counters = {
    blocks: 0,
    claimedDoneBlocks: 0,
    unstartedBlocks: 0,
    pathClaimsChecked: 0,
    lineRefsChecked: 0,
    unstartedBlocksProbed: 0,
    globsEvaluated: 0,
    propertiesChecked: 0,
  };

  const absDoc = resolve(root, docPath);
  if (!existsSync(absDoc)) {
    return { ok: false, unableToCheck: [`文書が無い: ${docPath}`], drifts, notes, unmapped, counters };
  }
  const docText = readFileSync(absDoc, 'utf8');
  const blocks = parseBlocks(docText);
  counters.blocks = blocks.length;
  counters.claimedDoneBlocks = blocks.filter((b) => b.status === 'CLAIMED_DONE').length;
  counters.unstartedBlocks = blocks.filter((b) => b.status === 'UNSTARTED').length;

  const unableToCheck = [];
  if (blocks.length === 0) {
    unableToCheck.push('`### #C… / #V…` 形式のブロックが1つも解析できなかった（見出し書式が変わった可能性）');
  }

  const exists = (p) => existsSync(join(root, p.split('/').join(sep)));

  // ── 検査 [1a][1b] ✅/▲ が主張するパスの実在 ───────────────────────────
  const negatedSkipped = [];
  for (const b of blocks) {
    if (b.status !== 'CLAIMED_DONE') continue;
    const fromHeading = extractRepoPaths(b.heading);
    const fromImpl = extractRepoPaths(b.implLine);
    for (const p of [...fromHeading.negated, ...fromImpl.negated]) {
      negatedSkipped.push({ block: b.id, docLine: b.line, path: p, exists: exists(p) });
    }
    const claims = [
      ...fromHeading.paths.map((p) => ({ p, where: '見出し' })),
      ...fromImpl.paths.map((p) => ({ p, where: '実装先' })),
    ];
    const seen = new Set();
    for (const c of claims) {
      if (seen.has(c.p + c.where)) continue;
      seen.add(c.p + c.where);
      counters.pathClaimsChecked++;
      if (!exists(c.p)) {
        drifts.push({
          check: '1',
          kind: 'CLAIMED_PATH_MISSING',
          block: b.id,
          docLine: b.line,
          detail: `${b.id} は実装済（✅/▲）と書いて ${c.where} に \`${c.p}\` を挙げているが、ツリーに存在しない`,
        });
      }
    }
  }

  // ── 検査 [1c] `path:line` 参照 ────────────────────────────────────────
  const { refs, unresolved } = extractLineRefs(docText);
  for (const r of refs) {
    counters.lineRefsChecked++;
    if (!exists(r.path)) {
      drifts.push({
        check: '1',
        kind: 'LINEREF_FILE_MISSING',
        docLine: r.docLine,
        detail: `\`${r.path}:${r.at}\` を参照しているが、ファイルが存在しない`,
      });
      continue;
    }
    const len = readFileSync(join(root, r.path.split('/').join(sep)), 'utf8').split(/\r?\n/).length;
    if (r.at > len) {
      drifts.push({
        check: '1',
        kind: 'LINEREF_OUT_OF_RANGE',
        docLine: r.docLine,
        detail: `\`${r.path}:${r.at}\` を参照しているが、当該ファイルは ${len} 行しかない`,
      });
    }
  }
  // 否定文脈で落としたパス。落としたこと自体を出す（黙って検査対象外にしない）。
  for (const n of negatedSkipped) {
    if (n.exists) {
      drifts.push({
        check: '1',
        kind: 'NEGATED_PATH_EXISTS',
        block: n.block,
        docLine: n.docLine,
        detail: `${n.block} は \`${n.path}\` を「ではない」と否定しているが、そのパスは実在する`,
      });
    } else {
      notes.push({
        check: '1',
        kind: 'NEGATED_PATH_SKIPPED',
        detail: `${n.block} の \`${n.path}\` は否定文脈（「ではない」）なので実在主張として数えなかった（実際に不在であることは確認済み）`,
      });
    }
  }

  if (unresolved.length) {
    notes.push({
      check: '1',
      kind: 'LINEREF_UNRESOLVABLE',
      detail: `ベース名だけの \`file:line\` 参照が ${unresolved.length} 件ある（どのディレクトリか文書からは決まらないので検査対象外）: ${[
        ...new Set(unresolved.map((u) => u.path)),
      ]
        .slice(0, 8)
        .join(', ')}${unresolved.length > 8 ? ' …' : ''}`,
    });
  }

  // ── 検査 [2] ★本体: ⬜ 未着手が嘘をついていないか ─────────────────────
  const tree = walkTree(root);
  const expectationById = new Map(UNSTARTED_EXPECTATIONS.map((e) => [e.id, e]));

  for (const b of blocks) {
    if (b.status !== 'UNSTARTED') continue;

    // (2a) 文書自身が実装先を書いているなら、それが最優先の期待パス。
    const declared = extractRepoPaths(b.implLine).paths;
    // (2b) 書いていないものは名前規約表から。
    const expectation = expectationById.get(b.id);

    if (declared.length === 0 && (!expectation || expectation.globs.length === 0)) {
      unmapped.push({
        block: b.id,
        docLine: b.line,
        reason: expectation
          ? expectation.basis
          : '`- **実装先**:` バレットが無く、UNSTARTED_EXPECTATIONS にも項目が無い',
        outOfRepo: Boolean(expectation && expectation.outOfRepo),
      });
      continue;
    }

    counters.unstartedBlocksProbed++;
    const hits = [];

    for (const p of declared) {
      counters.globsEvaluated++;
      if (exists(p)) hits.push({ path: p, via: `実装先 \`${p}\`` });
    }
    if (expectation) {
      for (const g of expectation.globs) {
        counters.globsEvaluated++;
        const re = globToRegExp(g);
        for (const entry of tree) {
          if (!re.test(entry.path)) continue;
          // A name convention says "if this block were started, something called
          // this would grow". Prose is not that something. `compiler/**/*envelope*`
          // matched `compiler/llvm-pass/docs/envelope-notes.md` -- a memo about the
          // block is exactly what an UNSTARTED block is expected to accumulate, so
          // counting it as the artefact makes planning look like implementing. The
          // `- **実装先**:` bullets above are unaffected: those are transcribed
          // paths, and if the document names a document, that is its claim to make.
          if (isProsePath(entry.path)) continue;
          hits.push({ path: entry.path, via: `名前規約 \`${g}\``, dir: entry.dir });
        }
      }
    }

    if (hits.length === 0) continue;

    const source = hits.filter((h) => !isTestPath(h.path));
    const testsOnly = source.length === 0;
    const record = {
      check: '2',
      kind: testsOnly ? 'UNSTARTED_BUT_TESTS_EXIST' : 'UNSTARTED_BUT_ARTEFACT_EXISTS',
      block: b.id,
      docLine: b.line,
      basis: expectation ? expectation.basis : '文書の `- **実装先**:` バレット',
      hits: [...new Set(hits.map((h) => h.path))].sort(),
      detail:
        `${b.id} は「⬜ 未着手」と書かれているが、期待成果物が実在する: ` +
        [...new Set(hits.map((h) => h.path))].sort().join(', '),
    };
    if (testsOnly) notes.push(record);
    else drifts.push(record);
  }

  // (2c) 文書が自分で出した「読み手は 0」の主張を再実行する。
  //      これは名前規約ではなく、**文書がオラクルを供給している**唯一の経路。
  const zeroClaims = extractZeroReaderClaims(docText);
  for (const claim of zeroClaims) {
    const leaf = claim.key.split('.').slice(1).join('.');
    const re = new RegExp(`policy\\s*\\??\\.\\s*${leaf.replace(/\./g, '\\s*\\??\\.\\s*')}\\b`);
    const readers = [];
    for (const entry of tree) {
      if (entry.dir) continue;
      if (!/\.(mjs|cjs|js|ts|tsx)$/.test(entry.path)) continue;
      if (isTestPath(entry.path)) continue;
      let text;
      try {
        text = readFileSync(join(root, entry.path.split('/').join(sep)), 'utf8');
      } catch {
        continue;
      }
      if (!re.test(text)) continue;
      // コメント行だけの一致か、実コードでも読んでいるかを分けて出す。
      const code = text
        .split(/\r?\n/)
        .some((l) => re.test(l) && !/^\s*(\/\/|\*|\/\*)/.test(l));
      readers.push({ path: entry.path, code });
    }
    counters.globsEvaluated++;
    if (readers.length > 0) {
      drifts.push({
        check: '2',
        kind: 'ZERO_READER_CLAIM_FALSIFIED',
        docLine: claim.docLine,
        detail:
          `文書は \`${claim.key}\` の読み手を **0** と書いているが、非テストの読み手が ${readers.length} 本ある: ` +
          readers.map((r) => `${r.path}${r.code ? '' : '(コメントのみ)'}`).join(', '),
        hits: readers.map((r) => r.path),
      });
    }
  }

  // ── 検査 [3] compiler/schema/properties.json の内部整合 ────────────────
  const propsRel = 'compiler/schema/properties.json';
  if (!exists(propsRel)) {
    unableToCheck.push(`${propsRel} が無いので検査 [3] は走らなかった`);
  } else {
    let cat;
    try {
      cat = JSON.parse(readFileSync(join(root, propsRel.split('/').join(sep)), 'utf8'));
    } catch (err) {
      unableToCheck.push(`${propsRel} を JSON として読めなかった: ${err.message}`);
    }
    if (cat) {
      const extractors = cat.extractors ?? {};
      const known = new Set(Object.keys(extractors));
      const props = Array.isArray(cat.properties) ? cat.properties : [];
      counters.propertiesChecked = props.length;
      if (props.length === 0) {
        unableToCheck.push(`${propsRel} に properties[] が無いので検査 [3] は実質走っていない`);
      }

      for (const [name, ex] of Object.entries(extractors)) {
        if (ex && typeof ex.path === 'string' && isRepoRelative(ex.path + '/') && !exists(ex.path)) {
          drifts.push({
            check: '3',
            kind: 'EXTRACTOR_PATH_MISSING',
            detail: `extractor \`${name}\` の path \`${ex.path}\` が存在しない`,
          });
        }
      }

      const byKind = new Map();
      for (const p of props) {
        if (!byKind.has(p.kind)) byKind.set(p.kind, []);
        byKind.get(p.kind).push(p);

        if (p.status === 'implemented' && !p.extractor) {
          drifts.push({
            check: '3',
            kind: 'IMPLEMENTED_WITHOUT_EXTRACTOR',
            detail: `\`${p.id}\` は status=implemented だが extractor が null`,
          });
        }
        if (p.extractor && !known.has(p.extractor)) {
          drifts.push({
            check: '3',
            kind: 'UNKNOWN_EXTRACTOR',
            detail: `\`${p.id}\` の extractor \`${p.extractor}\` が extractors に無い`,
          });
        }
        const observeAt = Array.isArray(p.observeAt) ? p.observeAt : [];
        const implCps = observeAt.filter((o) => o.status === 'implemented');
        for (const o of observeAt) {
          if (o.extractor && !known.has(o.extractor)) {
            drifts.push({
              check: '3',
              kind: 'UNKNOWN_EXTRACTOR',
              detail: `\`${p.id}\` の checkpoint ${o.checkpoint} が未知の extractor \`${o.extractor}\` を指している`,
            });
          }
          if (o.status === 'implemented' && (!o.extractor || !o.component)) {
            drifts.push({
              check: '3',
              kind: 'CHECKPOINT_IMPLEMENTED_WITHOUT_EXTRACTOR',
              detail: `\`${p.id}\` の checkpoint ${o.checkpoint} は implemented だが extractor/component が欠けている`,
            });
          }
          if (!o.extractor && o.status !== 'unimplemented') {
            drifts.push({
              check: '3',
              kind: 'CHECKPOINT_STATUS_WITHOUT_EXTRACTOR',
              detail: `\`${p.id}\` の checkpoint ${o.checkpoint} は extractor null なのに status=${o.status}`,
            });
          }
        }
        // `partial` は「一部の checkpoint は実装済みで、残りはそうでない」という意味の語であって、
        // 実装済み checkpoint の存在はその定義そのもの ── 矛盾ではない。旧規則はここを矛盾と読み、
        // `notappear.forbidden-external-call`（IR では測れる／object と linked では測れない）を
        // 恒久的に DRIFT にしていた。カタログを黙らせる方法は status を `implemented` に上げることだけで、
        // それは「測っていない checkpoint を測ったことにする」＝このカタログが 2026-08-10 に直した誤りの再演。
        // 検査を満たす唯一の道が過大主張なら、その検査は過大主張を要求している。
        //
        // 矛盾として残すのは、`partial` を名乗れない status のとき。`unimplemented` を名乗りながら
        // 実装済み checkpoint を持つのは、部分実装の記述漏れであって、部分実装ではない。
        const partialIsHonest =
          p.status === 'partial' && implCps.length < observeAt.length;
        if (implCps.length > 0 && p.status !== 'implemented' && !partialIsHonest) {
          drifts.push({
            check: '3',
            kind: 'KIND_VS_CHECKPOINT_MISMATCH',
            detail:
              `\`${p.id}\` は property 側 status=${p.status} なのに checkpoint 側に implemented がある（${implCps
                .map((o) => o.checkpoint)
                .join(', ')}）` +
              (p.status === 'partial'
                ? ' ── partial を名乗っているが checkpoint が全て implemented なので、部分ではなく implemented'
                : ''),
          });
        }
        if (implCps.length === 0 && p.status === 'implemented') {
          drifts.push({
            check: '3',
            kind: 'IMPLEMENTED_WITHOUT_CHECKPOINT',
            detail: `\`${p.id}\` は status=implemented だが implemented な checkpoint が1つも無い`,
          });
        }
      }

      const coverage = cat.kindCoverage ?? {};
      for (const kind of byKind.keys()) {
        if (!(kind in coverage)) {
          drifts.push({
            check: '3',
            kind: 'KIND_NOT_IN_COVERAGE',
            detail: `properties[] に kind=${kind} があるが kindCoverage に記述が無い`,
          });
        }
      }
      for (const [kind, prose] of Object.entries(coverage)) {
        if (kind.startsWith('_')) continue;
        if (!byKind.has(kind)) {
          drifts.push({
            check: '3',
            kind: 'COVERAGE_KIND_UNUSED',
            detail: `kindCoverage に ${kind} があるが properties[] に該当が無い`,
          });
          continue;
        }
        const label = String(prose).split(/\s+--\s+|\s+—\s+/)[0].trim().toLowerCase();
        const list = byKind.get(kind);
        const allUnimpl = list.every((p) => p.status === 'unimplemented' && !p.extractor);
        const allImpl = list.every((p) => p.status === 'implemented');
        if (!['none', 'partial', 'full'].includes(label)) {
          notes.push({
            check: '3',
            kind: 'COVERAGE_LABEL_UNPARSED',
            detail: `kindCoverage.${kind} の先頭語 "${label}" が none/partial/full のどれでもないので集計と突合できない`,
          });
          continue;
        }
        if (label === 'none' && !allUnimpl) {
          drifts.push({
            check: '3',
            kind: 'COVERAGE_SAYS_NONE_BUT_ENTRIES_DISAGREE',
            detail: `kindCoverage.${kind} は "none" だが、per-entry には ${list
              .filter((p) => p.status !== 'unimplemented' || p.extractor)
              .map((p) => `${p.id}=${p.status}`)
              .join(', ')} がある`,
          });
        }
        if (label === 'full' && !allImpl) {
          drifts.push({
            check: '3',
            kind: 'COVERAGE_SAYS_FULL_BUT_ENTRIES_DISAGREE',
            detail: `kindCoverage.${kind} は "full" だが、per-entry に implemented でないものがある`,
          });
        }
        if (label === 'partial' && allImpl) {
          drifts.push({
            check: '3',
            kind: 'COVERAGE_SAYS_PARTIAL_BUT_ALL_IMPLEMENTED',
            detail: `kindCoverage.${kind} は "partial" だが、per-entry は全て implemented`,
          });
        }
        if (label === 'partial' && allUnimpl) {
          // 散文がカタログ外のコンポーネントを根拠にしている場合がある
          // （must-originate-from が elf-verifier を挙げているのがそれ）。
          // 矛盾と断定できないので NOTE に留める。
          notes.push({
            check: '3',
            kind: 'COVERAGE_PARTIAL_WITH_NO_ENTRY',
            detail: `kindCoverage.${kind} は "partial" だが、properties[] の該当は全て unimplemented（散文がカタログ外の実装を根拠にしている可能性。人間が読むこと）`,
          });
        }
      }
    }
  }

  // ── 「検査が走らなかった」の判定 ────────────────────────────────────
  if (counters.pathClaimsChecked === 0) {
    unableToCheck.push('✅/▲ ブロックからリポジトリ相対パスの主張が1本も抽出できなかった（検査 [1] は空振り）');
  }
  // 「⬜ が1本も検査できなかった」の分母から、**リポジトリ外だと明示的に宣言済み**の
  // ブロックを外す。#C8 のような執筆ブロックはツリーに成果物が生えないと最初から
  // 書いてあり、検査できないことが検査の失敗ではない。ここを外さないと、他の ⬜ が
  // 全部片付いた瞬間に ── つまり作業が進むほど ── 恒久的に exit 3 になる。
  //
  // 警報は残す。外すのは「宣言済みで、なおかつ 対応不明 に名前が出ているもの」だけで、
  // 未知の ⬜（マッピング欄に entry が無い新設ブロック）は今までどおり分母に入り、
  // 1本も検査できなければ exit 3 になる。そちらが本当の drift 前兆。
  const unstartedOutOfRepo = unmapped.filter((u) => u.outOfRepo).length;
  const unstartedProbable = counters.unstartedBlocks - unstartedOutOfRepo;
  counters.unstartedBlocksOutOfRepo = unstartedOutOfRepo;
  counters.unstartedBlocksProbable = unstartedProbable;
  if (unstartedProbable > 0 && counters.unstartedBlocksProbed === 0) {
    unableToCheck.push('⬜ ブロックはあるのに、期待成果物を1本も検査できなかった（検査 [2] は空振り）');
  }

  return {
    ok: drifts.length === 0 && unableToCheck.length === 0,
    unableToCheck,
    drifts,
    notes,
    unmapped,
    counters,
  };
}

// ── 表示 ──────────────────────────────────────────────────────────────────

function render(report, { root, docPath }) {
  const L = [];
  L.push('check-doc-drift — ' + docPath + ' ↔ ' + root);
  L.push('');
  L.push(
    `解析: ブロック ${report.counters.blocks} 本（✅/▲ ${report.counters.claimedDoneBlocks} / ⬜ ${report.counters.unstartedBlocks}）` +
      ` ・ パス主張 ${report.counters.pathClaimsChecked} 本 ・ path:line 参照 ${report.counters.lineRefsChecked} 本` +
      ` ・ ⬜ 期待検査 ${report.counters.unstartedBlocksProbed}/${report.counters.unstartedBlocksProbable} ブロック` +
      `（うちリポジトリ外と宣言済み ${report.counters.unstartedBlocksOutOfRepo} 本は分母外）/ ${report.counters.globsEvaluated} 条件` +
      ` ・ properties ${report.counters.propertiesChecked} 件`,
  );
  L.push('');

  const byCheck = (n) => report.drifts.filter((d) => d.check === n);
  const titles = {
    1: '[1] ✅/▲ が主張するパスの実在',
    2: '[2] ★本体: ⬜ 未着手が嘘をついていないか',
    3: '[3] compiler/schema/properties.json の内部整合',
  };
  for (const n of ['1', '2', '3']) {
    L.push(titles[n]);
    const ds = byCheck(n);
    if (ds.length === 0) L.push('  DRIFT なし');
    for (const d of ds) {
      L.push(`  DRIFT ${d.kind}${d.docLine ? ` (doc:${d.docLine})` : ''}`);
      L.push(`    ${d.detail}`);
      if (d.basis) L.push(`    期待の根拠: ${d.basis}`);
    }
    L.push('');
  }

  if (report.notes.length) {
    L.push('NOTE（DRIFT にはしないが人間が読むもの）');
    for (const n of report.notes) L.push(`  [${n.check}] ${n.kind}: ${n.detail}`);
    L.push('');
  }

  L.push('対応不明（⬜ ブロックのうち、期待成果物をツリー上に定義できなかったもの）');
  if (report.unmapped.length === 0) L.push('  なし');
  for (const u of report.unmapped) {
    L.push(`  ${u.block} (doc:${u.docLine})${u.outOfRepo ? ' — 成果物がリポジトリ外' : ''}`);
    L.push(`    ${u.reason}`);
  }
  L.push('');

  if (report.unableToCheck.length) {
    L.push('★ 検査が走らなかった項目（exit 3）');
    for (const u of report.unableToCheck) L.push(`  ${u}`);
    L.push('');
  }

  L.push(
    `結果: DRIFT ${report.drifts.length} 件 / NOTE ${report.notes.length} 件 / 対応不明 ${report.unmapped.length} 件`,
  );
  return L.join('\n');
}

export function exitCodeFor(report) {
  if (report.unableToCheck.length > 0) return 3;
  return report.drifts.length > 0 ? 1 : 0;
}

function main(argv) {
  let root = DEFAULT_ROOT;
  let docPath = DEFAULT_DOC;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') json = true;
    else if (a === '--root') root = resolve(argv[++i] ?? '');
    else if (a === '--doc') docPath = argv[++i] ?? '';
    else if (a === '--help' || a === '-h') {
      process.stdout.write(
        'usage: node scripts/check-doc-drift.mjs [--json] [--root <dir>] [--doc <md>]\n' +
          '  exit 0 = 検査が全部走って DRIFT なし / 1 = DRIFT あり / 2 = 使い方の誤り / 3 = 検査が走らなかった\n',
      );
      return 0;
    } else {
      process.stderr.write(`unknown argument: ${a}\n`);
      return 2;
    }
  }
  let report;
  try {
    report = runDriftCheck({ root, docPath });
  } catch (err) {
    process.stderr.write(`internal error: ${err && err.stack ? err.stack : err}\n`);
    return 2;
  }
  process.stdout.write(json ? JSON.stringify(report, null, 2) + '\n' : render(report, { root, docPath }) + '\n');
  return exitCodeFor(report);
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) process.exit(main(process.argv.slice(2)));
