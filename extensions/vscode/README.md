# VibeGuard VS Code 拡張（最小版）

`@vibeguard/analyzer-core` を呼び出して、開いているファイルにセキュリティ Diagnostics を表示する最小拡張。

## 機能

- 保存時スキャン（既定 `fast` モード、設定で変更可）
- コマンド `VibeGuard: Scan File`（`standard` モード）
- Diagnostics 表示（Error / Warning / Info を severity から導出）
- ファイルクローズ時に Diagnostics クリア

設計書 §10.2 の最小スコープのみ。選択範囲スキャン・Code Action・サイドバー・SARIF
出力は Phase 1.5 以降。

## 開発（F5 起動）

リポジトリのルートで:

```bash
npm install
npm run build
```

その後、`extensions/vscode/` を VS Code で開き、F5 で **Run VibeGuard Extension**
を起動すると Extension Development Host が立ち上がる。

検証手順:

1. 起動した新しいウィンドウで `samples/vulnerable/xss.js` 等を開く
2. Cmd/Ctrl+S で保存 → Problems パネルに findings が並ぶ
3. コマンドパレット → `VibeGuard: Scan File` → 結果が出る
4. 設定 `vibeguard.scanOnSaveMode` を `fast` / `standard` で切り替えて検出数の差を確認

## 設定項目

| 設定 | 既定 | 説明 |
|---|---|---|
| `vibeguard.scanOnSave` | `true` | 保存時スキャンの ON/OFF |
| `vibeguard.scanOnSaveMode` | `fast` | 保存時のスキャンモード（`fast` / `standard`） |
