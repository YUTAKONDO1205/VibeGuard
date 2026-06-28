# A1. ReDoS / 計算量耐性 〔P0〕

未信頼な被スキャンファイルで、正規表現ルールの破滅的バックトラッキングを誘発し
スキャン全体をハングできるか。設計は [../../SCOPE.md](../../SCOPE.md) §3 A1 を参照。

- 仮説: `runRegex`（[matcher-utils.ts](../../../packages/rules/src/matcher-utils.ts)）に時間/サイズ上限が無い。
- 予定ハーネス: `scripts/sec-a1-redos.mjs`（ルール正規表現抽出 → 静的判定 → n–time 実測）。
- 成果物: 攻撃コーパス・n–time 表・緩和案。
