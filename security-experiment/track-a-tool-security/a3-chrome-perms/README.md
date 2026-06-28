# A3. Chrome 拡張の権限・攻撃面監査 〔P1〕

Manifest V3 権限の最小性と、悪意あるページからの権限/コード奪取経路の不在を確認。
設計は [../../SCOPE.md](../../SCOPE.md) §3 A3 を参照。

- 対象: `extensions/chrome/`（manifest, background, side-panel, content）。
- 成果物: 権限表・データフロー図・指摘。
