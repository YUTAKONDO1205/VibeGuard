# AGENTS.md

VibeGuard リポジトリで Codex（および同等の AI 実装エージェント）が従うべき運用ルール。

設計書 §9 の Codex 実装ハーネス設計を、実装に落とし込んだ常駐ガイドとして本ファイルを置く。

---

## 1. プロジェクトの目的

VibeGuard は **AI 生成コードに特化したセキュリティ診断基盤**。次の 3 段階で同一の解析コアを使い、判定基準のズレを起こさないことを最重要原則とする。

- **開発中**：VS Code 拡張（保存時 / 手動スキャン → Diagnostics）
- **閲覧中**：Chrome 拡張（GitHub PR 差分 / 選択コード → Side Panel）
- **マージ前**：GitHub Actions / CLI（SARIF + PR コメント）

すべての解析ロジックは `packages/analyzer-core` および `packages/rules` に集約し、エディタ・ブラウザ・CI の各エントリポイントは入出力の薄い殻に留める。

---

## 2. デフォルトの開発ループ

```
Planner → Generator → Evaluator → (PASS なら次タスク / FAIL なら戻す)
```

- **非自明な機能追加は必ず Planner を通す**
- 1 タスクごとに Generator → Evaluator で必ず検証する
- 検証未実施で「完成」としない
- UI 変更（VS Code / Chrome）があるときはブラウザ実行画面で挙動を確認する

エージェント定義ファイルは `.codex/agents/{planner,generator,evaluator}.toml` を参照。

---

## 3. Planner / Generator / Evaluator の使い分け

| 役割 | 入力 | 出力 |
|---|---|---|
| **Planner** | 曖昧な要件 | スコープ・非スコープ、受け入れ条件、実装順序を含むタスクリスト |
| **Generator** | 1 タスク | 最小差分のコード変更 + 必要最小限のテスト |
| **Evaluator** | 変更後のコード | テスト・静的解析・必要なら UI 検証 → `PASS` / `PASS WITH GAPS` / `FAIL` |

Generator は一度に 1 タスクのみ。複数タスクを束ねたいときは Planner に戻し、依存関係を整理してから流す。

---

## 4. Definition of Done

PR / 変更を「完了」と見なす最低基準。

1. `npm run build` がグリーン
2. `npm test` がグリーン
3. `samples/safe` のスキャン結果が **0 finding**（false positive 検出）
4. `samples/vulnerable` のスキャン結果が **15 件以上**（regression 検出）
5. ルール追加時は `samples/` または `rules.test.ts` に対応する vulnerable / safe ケースが入っている
6. 新ルールは `VG-<INJ|AUTH|SEC|CRYPTO|QUAL>-NNN` 形式の ID を持ち、`remediation.why` / `remediation.how` が埋まっている
7. UI 変更がある場合、PR 本文に挙動のスクリーンショットを添付
8. パフォーマンス影響があり得る変更（diff スキャン / 新規ヘビー級ルール / 外部スキャナ統合）は `samples/vulnerable` の実行時間ベースラインを記録

---

## 5. モノレポ前提の開発ルール

- **解析ロジックは `packages/analyzer-core` と `packages/rules` 以外に書かない**
- `apps/cli`・`extensions/vscode`・`extensions/chrome` は薄いアダプタに留め、ルール判定や severity 計算は持たせない
- パッケージ間の依存は **下から上への一方向**：`findings-schema` → `rules` → `remediation-engine` / `sarif-adapter` → `analyzer-core` → `apps/*` / `extensions/*`
- `node:fs` / `node:path` / `node:os` を使うのは `analyzer-core` の `file-scanner.ts` と `apps/cli` のみ。Chrome 向けバンドルが壊れるため、それ以外で fs を増やさない
- ルール追加時は `packages/rules/src/rules/<category>.ts` の既存パターンに合わせる。ID とカテゴリの命名規約は `packages/rules/src/registry.test.ts` で機械検証されている

---

## 6. テストとレポートの最低基準

| 種別 | 最低限 |
|---|---|
| ユニットテスト | 各 `packages/*/src/**/*.test.ts` を vitest で。新規モジュールはテストとセットで追加 |
| ルール単体 | `samples/vulnerable` に「検出されるべき」ケース、`samples/safe` に「検出されてはいけない」ケースを 1 つ以上 |
| Self-scan | `.github/workflows/security-scan.yml` の `self-scan` ジョブが SARIF を Code Scanning にアップロードする。誤検知が出たら **suppress コメント**（[suppress.ts](packages/analyzer-core/src/suppress.ts) 参照）で対処してから severity ゲートを通す |
| 報告 | Evaluator は PASS / PASS WITH GAPS / FAIL を必ず返す。GAPS / FAIL のときは未検証箇所と残課題を箇条書きで明示する |

---

## 7. 差分スキャン

PR レビューでは「この PR で何が*新しく*入るのか」を最短で把握したい。CLI の `--diff <range>` はこの用途専用：

```bash
node apps/cli/dist/index.js --diff origin/main...HEAD --format markdown
```

- 内部で `git diff <range> --unified=0` を実行
- 変更ファイルを working tree から読み込み、analyzer で**フルスキャン**（regex の context を保つため）
- 追加行と重なる finding のみ採用

CI の `pr-diff-scan` ジョブは PR ごとに走り、別 sticky コメント（`vibeguard-diff` ヘッダ）で結果を貼る。`high` 以上で失敗。

実装は [apps/cli/src/diff.ts](apps/cli/src/diff.ts) に集中。fs / git 依存があるため、Chrome 拡張からは使えない（PR 差分はブラウザ側で別途 DOM/API 抽出する）。

---

## 8. Suppress コメント運用

ルール定義ファイルやテストフィクスチャは、検出対象の文字列（`eval(` / dummy token / `verify=False` など）を**意図的に**含む。これらは以下の pragma で除外する。

```js
eval(payload); // vibeguard:disable-line VG-INJ-004

// vibeguard:disable-next-line VG-INJ-004
exec(userInput);

// vibeguard:disable-file VG-AUTH-003 VG-AUTH-004
```

- ルール ID を省略すると **その行 / ファイルのすべてのルール** を抑制する
- プロダクトコードでは「なぜ抑制してよいのか」をコメントで残す
- テストファイルや rules.ts ではファイル冒頭に `disable-file` を置くのが標準

---

## 9. Chrome 拡張のルール

`extensions/chrome/` は Side Panel + service worker（Manifest V3）。実装時の固定ルール：

- analyzer-core を使うときは **必ず `@vibeguard/analyzer-core/browser`** から import する。default export は `node:fs` / `node:path` に依存するためバンドルが壊れる
- Side Panel UI と service worker は **同じ shared 型**（`src/shared/messages.ts`）でやり取りする。新しいメッセージを足すときはここに型を追加する
- 外部 API への送信は禁止。スキャンは完全にローカル
- 静的アセット（`manifest.json` / HTML / CSS / icons）は `copy-static.mjs` 経由で `dist/` にコピーする。HTML/CSS の置き場所は `src/sidepanel/` のまま動かさない
- 拡張の動作確認は `npm run build -w vibeguard-chrome` 後に `chrome://extensions` でアンパック読み込み → Side Panel を開いて貼り付けスキャン / Extract / 右クリック選択スキャンの 3 経路を最低 1 回ずつ確認する

---

## 10. 参考

- 設計書: [設計書.md](設計書.md)
- 開発ロードマップ: [README.md §開発フェーズ](README.md)
- ルール一覧: [packages/rules/src/](packages/rules/src/)
- Codex 設定: [.codex/](.codex/)
