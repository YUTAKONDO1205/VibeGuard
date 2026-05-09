# VibeGuard

[![CI](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/ci.yml)
[![Security Scan](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/security-scan.yml)

開発者: 近藤悠太 (Kondo Yuta)

AI生成コードに特化したセキュリティ診断基盤。**開発中（VS Code）**・**閲覧中（Chrome）**・**マージ前（GitHub Actions / CLI）** の3段階で同一の解析コアを使ってコードを検査し、危険箇所と修正方針を提示する。

## 概要

生成AIが書いたコードは「とりあえず動く」状態のまま採用されがちで、入力検証の欠落・ハードコードされた秘密情報・認証スキップ・例外握りつぶしなどの典型的な地雷を抱えやすい。VibeGuard はこれらを早期に検出するための統合診断基盤であり、解析ロジックを共通パッケージへ集約することで、エディタ・ブラウザ・CI で判定基準がズレないことを最重要原則としている。

詳細は [設計書.md](設計書.md) を参照。

## モノレポ構成

```text
vibeguard-codex/
├─ AGENTS.md                  # Codex 向けプロジェクト全体ルール
├─ 設計書.md                   # 詳細設計書 v0.2
├─ .codex/                    # Codex プロジェクト設定 / エージェント定義
│  ├─ config.toml
│  └─ agents/{planner,generator,evaluator}.toml
├─ apps/
│  └─ cli/                    # ローカル実行・CI 向け CLI
├─ packages/
│  ├─ analyzer-core/          # 共通診断エンジン
│  ├─ rules/                  # ルール定義・実行ロジック
│  ├─ findings-schema/        # 検出結果の標準スキーマ
│  ├─ remediation-engine/     # 修正案生成
│  └─ sarif-adapter/          # SARIF 変換
└─ samples/
   ├─ vulnerable/             # 検出されるべき危険コード
   └─ safe/                   # 検出されてはいけない安全コード
```

将来的に `extensions/vscode`・`extensions/chrome`・`packages/scanner-semgrep` などを追加予定。

## セットアップ

前提：Node.js 18 以上。

```bash
npm install
npm run build
```

## CLI の使い方

```bash
# ディレクトリをスキャン（人間向け出力）
node apps/cli/dist/index.js ./samples/vulnerable

# SARIF を出力して GitHub Code Scanning にアップロードできる形にする
node apps/cli/dist/index.js ./src --format sarif --out report.sarif

# Critical 検出時のみ非ゼロ終了
node apps/cli/dist/index.js suspicious.py --fail-on critical

# PR で追加された行だけをスキャン（git diff <range> --unified=0 を内部で使用）
node apps/cli/dist/index.js --diff origin/main...HEAD --format markdown
```

主なオプション：

| オプション | 説明 |
|---|---|
| `--format <human\|json\|sarif\|markdown>` | 出力形式（デフォルト: human）。`markdown` は PR コメント向け |
| `--out <file>` | 結果をファイルへ書き出す |
| `--mode <fast\|standard\|deep>` | スキャン深度（デフォルト: standard） |
| `--fail-on <level>` | 指定 severity 以上で終了コードを非ゼロにする |
| `--ignore <name>` | 追加の除外ディレクトリ名（複数指定可） |
| `--diff <range>` | `git diff <range> --unified=0` で追加された行のみスキャン |
| `--known-only` | 既知言語の拡張子のみスキャン |
| `--no-remediation` | 修正案生成をスキップ |

## テスト

```bash
npm test
```

各パッケージの `*.test.ts` を vitest で実行する。

## GitHub Actions

リポジトリには 2 本のワークフローを同梱している。

| Workflow | 役割 |
|---|---|
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | `npm ci` → `npm run build` → `npm test` の基本ゲート |
| [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) | self-scan / samples / pr-diff-scan の 3 ジョブ。self-scan は SARIF を Code Scanning にアップロード + PR sticky コメント、品質ゲートは samples、PR の追加行は pr-diff-scan で別コメント |

### self-scan ジョブ
VibeGuard 自身を `--fail-on never` でスキャンし、結果を SARIF として Security タブへ、Markdown として PR コメントへ反映する。**情報提示のみで build は止めない**：ルール定義ファイル ([packages/rules/src/rules/](packages/rules/src/rules/)) には `eval()` や dummy credential など検出対象のリテラルが正規表現の例として含まれ、テストファイルには意図的な脆弱コードが入っているため、self-scan で 0 件を要求するのは構造上無理がある。

### samples ジョブ
ルール正当性の真の品質ゲート。

- [`samples/safe`](samples/safe) → 0 findings であること（false positive 検出）
- [`samples/vulnerable`](samples/vulnerable) → 15 件以上検出されること（regression 検出）

### pr-diff-scan ジョブ
PR で追加された行だけをスキャンし、別 sticky コメント（`vibeguard-diff` ヘッダ）として投稿する。`high` 以上で失敗。`origin/<base_ref>...HEAD` を `git diff --unified=0` で取得し、変更ファイルを working tree から読み込んでフルスキャン → 追加行と重なる finding のみ採用する。

### 注意
fork からの PR ではコメント投稿はスキップされる（`pull-requests: write` 権限の制約）。初回 main push の後は GitHub の Security タブに結果が集約される。

## VS Code 拡張

`extensions/vscode/` に最小拡張を同梱。F5 で Extension Host を起動して開発できる。

| 機能 | 起動方法 |
|---|---|
| 保存時スキャン | デフォルト ON。`vibeguard.scanOnSave` で OFF 可、`vibeguard.scanOnSaveMode` で `fast` / `standard` を選択 |
| 手動スキャン | コマンドパレット → `VibeGuard: Scan File` |
| 選択範囲スキャン | エディタ右クリック → `VibeGuard: Scan Selection`（フルファイルスキャン → 選択範囲の finding のみ表示） |
| Diagnostics | severity をエラー / 警告 / 情報にマッピング |
| Code Action | 黄色電球 → `suppress <ruleId> on this line`（`vibeguard:disable-next-line` をコメント挿入）/ `show remediation` |
| Findings サイドバー | エクスプローラ内の **VibeGuard Findings** ビュー。ファイル → finding 階層、クリックで該当行へジャンプ |

## Chrome 拡張

`extensions/chrome/` に Manifest V3 ベースの最小拡張を同梱（Phase 3 着手）。analyzer-core の `./browser` サブパスを使い、`node:fs` / `node:path` を含まないバンドルを Side Panel から実行する。

| 機能 | 起動方法 |
|---|---|
| Side Panel 表示 | ツールバーの VibeGuard アイコンをクリック |
| 貼り付けスキャン | Side Panel のテキストエリアにコードを貼って「Scan」 |
| ページ抽出 | Side Panel の「Extract from page」で表示中タブの `<pre><code>` を集めて自動スキャン |
| 選択範囲スキャン | 任意ページでテキスト選択 → 右クリック → `Scan with VibeGuard`（Side Panel が開いて即スキャン） |
| 言語指定 | `auto-detect` または js / ts / python / go / java / ruby / php / csharp |

ビルド：

```bash
npm run build -w vibeguard-chrome
```

`extensions/chrome/dist/` を `chrome://extensions` の「パッケージ化されていない拡張機能を読み込む」で指定するとそのまま動作する。`npm run watch -w vibeguard-chrome` で esbuild が監視ビルドする。

## 開発フェーズ

| Phase | 対象 |
|---|---|
| 1 (MVP) | analyzer-core、基本ルール 20〜30 個、findings-schema、SARIF 出力、CLI、VS Code 拡張最小版 |
| 2 | GitHub Actions、PR コメント、fail 判定、CodeQL 共存 |
| 3 | Chrome 拡張（コード抽出 / Side Panel / PR 差分スキャン） |
| 4 | AI 修正提案高度化、組織ポリシー、言語追加、ダッシュボード |

現在は Phase 1 相当の実装が中心。

## 実装運用ルール（Codex ハーネス）

本リポジトリは Codex によるマルチエージェント実装を前提としており、以下の 3 役で責務を分離する。

- **Planner**：曖昧な要件を実装可能なタスクへ分解する
- **Generator**：1 タスクだけを最小変更で実装する
- **Evaluator**：テスト・静的解析・必要ならブラウザ検証を行い PASS / PASS WITH GAPS / FAIL を返す

非自明な機能追加は必ず Planner を通し、1 タスク実装ごとに Evaluator で検証する。詳細は [AGENTS.md](AGENTS.md) を参照。

## ライセンス

未定（プロジェクト初期段階）。
