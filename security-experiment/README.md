# VibeGuard セキュリティ実証実験（security-experiment）

VibeGuard **というサービス自身**を対象とする、セキュリティ目線の実証実験ワークスペース。
VibeGuard は「AI生成コードのセキュリティスキャナ」を4チャネル（CLI・GitHub Action・
VS Code・Chrome）で提供するサービスである。セキュリティを売るサービスだからこそ、
**自分自身が攻撃面を持たないか／検出はすり抜けられないか**を実地で確かめる。

既存の `scripts/e1..e6` と [`docs/EVALUATION.md`](../docs/EVALUATION.md) は「機能品質
（一貫性・サンプル・diff削減・性能・confidence補正・SASTベースライン）」を扱う。本フォルダは
それと**重複しない**、セキュリティ目線の2軸を扱う：

1. **Track A — サービス自身の安全性（VibeGuard as a target）**
   ReDoS、ゼロ送信主張の実証、Chrome拡張の権限、サプライチェーン、未信頼入力での
   クラッシュ/ハング耐性。
2. **Track B — 敵対的検出耐性（red-team the detector）**
   正規表現ベース検出が、意味を保ったままの回避（難読化・AI生成回避コード・
   context-confidence の悪用）にどれだけ耐えるか。

> 位置づけ: 本実験は **VibeGuard 自リポジトリ（自サービス）を対象とした、正当な
> セキュリティ評価**であり、第三者システムへの攻撃を含まない。scope 境界は
> [SCOPE.md](SCOPE.md) の「対象外（Out of scope）」を参照。

## 構成

| パス | 内容 |
|---|---|
| [SCOPE.md](SCOPE.md) | 実験項目スコープ選定（脅威モデル・採否理由・各項目の仮説/手法/指標/成果物・優先度） |
| `track-a-tool-security/` | A1 ReDoS / A2 ゼロ送信 / A3 Chrome権限 / A4 サプライチェーン / A5 ファジング |
| `track-b-detection-robustness/` | B1 回避難読化 / B2 AI生成敵対コーパス / B3 context-confidence悪用 |
| `_results/` | 各実験の生成物（JSON/表/ログ）。gitignore候補。 |

各項目フォルダの `README.md` に、その実験単体の回し方を置く（E1–E6 と同じく
「番号付きスクリプト＋期待値」方式に揃える）。

## 進め方

1. [SCOPE.md](SCOPE.md) を確定（実験項目・指標・優先度の合意）。
2. 優先度 P0 の項目からハーネスを実装（`scripts/sec-*.mjs` として既存 `scripts/` 流儀に合わせる）。
3. 結果を `_results/` に出力 → 発見と緩和策をサービスにフィードバック（EVALUATION.md の
   E系と同じ追跡可能性を維持）。

## ステータス

- [x] フォルダ作成・スコープ設計（本コミット）
- [ ] 実験項目の優先度確定（合意待ち）
- [ ] P0 ハーネス実装
