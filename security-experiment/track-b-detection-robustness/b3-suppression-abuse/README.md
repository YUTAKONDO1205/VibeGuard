# B3. context-confidence / suppression の悪用 〔P0〕

本物の脆弱性をテストパス偽装/docstring偽装に置き、context-confidence の格下げで
action閾値未満へ隠蔽できるか。自作の目玉機能への敵対検証。設計は
[../../SCOPE.md](../../SCOPE.md) §3 B3 を参照。

- 対象挙動: [confidence.ts](../../../packages/analyzer-core/src/confidence.ts) の down-rank、`vibeguard:disable-next-line`。
- 成果物: 攻撃ケース・緩和案（critical は test パスでも格下げしない 等）。
