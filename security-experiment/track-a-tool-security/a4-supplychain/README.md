# A4. サプライチェーン / 依存・Action 監査 〔P1〕

既知脆弱依存・過剰な Action 権限・未ピン依存の有無を確認。設計は
[../../SCOPE.md](../../SCOPE.md) §3 A4 を参照。

- 手法: `npm audit` / SBOM（CycloneDX）/ `action.yml`・workflow の `permissions:` 最小化 / Action SHA ピン。
- 成果物: SBOM・監査表。
