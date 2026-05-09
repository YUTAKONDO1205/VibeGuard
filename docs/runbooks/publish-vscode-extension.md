# Runbook: Publish VibeGuard VS Code Extension

[`extensions/vscode/`](../../extensions/vscode/) を **Visual Studio Marketplace** と **Open VSX Registry** に公開する手順。

> **前提**：`@vscode/vsce` でパッケージング、`ovsx` で Open VSX に発行する。bundle 済みの `dist/extension.js` を含む `.vsix` を出すので、モノレポの workspace 依存はランタイムでは絡まない。

---

## 0. このリポジトリの状態（公開前チェック）

| 項目 | 場所 | 状態 |
|---|---|---|
| `private: true` を外した | [package.json](../../extensions/vscode/package.json) | ✅ |
| `publisher` を実 ID にした | [package.json](../../extensions/vscode/package.json) | ⚠️ 既定で `yutakondo`。Publisher 登録時に変えたら ここも揃える |
| `categories` / `keywords` / `repository` / `bugs` / `homepage` / `license` / `galleryBanner` | [package.json](../../extensions/vscode/package.json) | ✅ |
| `.vscodeignore` | [extensions/vscode/.vscodeignore](../../extensions/vscode/.vscodeignore) | ✅ |
| `CHANGELOG.md` | [extensions/vscode/CHANGELOG.md](../../extensions/vscode/CHANGELOG.md) | ✅ |
| `README.md` (ユーザー向け) | [extensions/vscode/README.md](../../extensions/vscode/README.md) | ✅ |
| `icon.png` (128×128) | `extensions/vscode/icon.png` | ❌ **未作成** — 公開前に必要 |
| `LICENSE` | `extensions/vscode/LICENSE` | ❌ 未配置（任意。リポジトリルートに LICENSE が出来たら symlink/コピー）|

---

## 1. Publisher 登録（一度だけ）

### 1.1 Web UI で Publisher を作る
1. https://marketplace.visualstudio.com/manage にログイン（Microsoft アカウント）
2. **Create publisher**：
   - **Publisher ID**: 半角英数（例：`yutakondo`）。**衝突不可・後から変更不可**
   - **Display name**: 表示名（例：`Yuta Kondo`）
3. 作成完了後、`extensions/vscode/package.json` の `publisher` フィールドが Publisher ID と一致しているか確認

### 1.2 Personal Access Token (PAT) を発行
**Azure DevOps の PAT** であって GitHub のではない。

1. https://dev.azure.com/ にログイン → 何でもいいので Organization を 1 個作る（例：`vibeguard-publish`）
2. 右上のユーザーアイコン → **Personal Access Tokens** → **+ New Token**
3. 設定：
   - Name: `vsce-publish`
   - Organization: **All accessible organizations** ← ここ重要（特定 org だと publish が通らない）
   - Expiration: 任意（`1 year` を推奨）
   - Scopes: **Custom defined** → **Marketplace** → **Manage** にチェック
4. **発行直後の画面でしかトークンは見えない**。安全な場所に保存

### 1.3 Open VSX のトークン（任意・推奨）
1. https://open-vsx.org にログイン（GitHub OAuth）
2. 右上 → **Settings** → **Access Tokens** → **Generate New Token**
3. 同じく安全な場所に保存

---

## 2. アイコン作成（公開前に必須）

`128x128` PNG が必要。`extensions/vscode/icon.png` に置く。

- 紫の盾モチーフ（GitHub Action の `branding: shield/purple` と揃えると一貫性が出る）
- `package.json` の `galleryBanner.color: "#4B2A8A"` と相性のいい色味
- アルファ透明 OK（Marketplace は背景に乗せて表示する）

`package.json` に **`"icon": "icon.png"`** を追加：

```json
{
  "displayName": "VibeGuard AICoding",
  "icon": "icon.png",
  ...
}
```

> 暫定で進めるなら、Chrome 拡張のプレースホルダ（`extensions/chrome/public/icons/icon-128.png`、68 byte の透明 PNG）をコピーすれば `vsce package` は通るが、Marketplace で「画像なし」のように見える。本番は本物に差し替えること。

---

## 3. パッケージング

### 3.1 vsce を入れる
```bash
npm i -D -w vibeguard-aicoding @vscode/vsce
```

### 3.2 ビルド + パッケージング
```bash
npm run build -w vibeguard-aicoding
cd extensions/vscode
# `--no-dependencies` 必須：これを付けないと vsce が monorepo の
# node_modules/@vibeguard/* シンボリックリンクを辿って親ディレクトリ
# (extensions/chrome の node_modules / packages/rules のテストフィクスチャ等)
# まで巻き込み、サイズが 10 MB を超え、しかも secret スキャナが
# テスト用のダミー GitHub トークンに反応して package が拒否される。
# 解析依存はすべて esbuild で dist/extension.js にバンドル済みなので
# vsce 側の依存解決は不要。
npx vsce package --no-dependencies
# → vibeguard-aicoding-0.1.0.vsix が出る（30〜50 KB）
```

### 3.3 .vsix の中身を確認
```bash
unzip -l vibeguard-aicoding-0.1.0.vsix
```

期待される内容：
```
extension.vsixmanifest
[Content_Types].xml
extension/package.json
extension/dist/extension.js
extension/README.md
extension/CHANGELOG.md
extension/icon.png
```

含まれてはいけないもの：
- `node_modules/**` — `.vscodeignore` で弾いている
- `src/**.ts` — 同上
- `*.map` — 同上

サイズ目安：bundle 後で 200〜500 KB 程度。1 MB を超えたら依存が漏れている可能性大。

---

## 4. ローカルで動作確認（公開前）

```bash
# インストール
code --install-extension vibeguard-aicoding-0.1.0.vsix

# 検証
# 1. 適当な脆弱コードを開いて保存 → Problems パネルに findings が出るか
# 2. Command Palette → "VibeGuard: Scan File" が動くか
# 3. Explorer サイドバーに "VibeGuard Findings" が出るか

# アンインストール
code --uninstall-extension yutakondo.vibeguard-aicoding
```

ここで OK が出るまで `vsce publish` しない（公開後の差し替えは可能だが、利用者には更新通知が飛ぶので望ましくない）。

---

## 5. Visual Studio Marketplace に公開

### 5.1 ログイン
```bash
cd extensions/vscode
npx vsce login yutakondo   # ← 実 publisher ID
# PAT を貼り付けるプロンプトが出る
```

### 5.2 公開
```bash
npx vsce publish --packagePath vibeguard-aicoding-0.1.0.vsix --no-dependencies
```

PAT を OS keychain に保存したくないときは、`vsce login` を省いて環境変数で渡してもよい：

```powershell
$env:VSCE_PAT="<PAT>"
npx vsce publish --packagePath vibeguard-aicoding-0.1.0.vsix --no-dependencies
```

公開直後は Marketplace のインデックスに反映されるまで 5〜30 分。URL：
```
https://marketplace.visualstudio.com/items?itemName=yutakondo.vibeguard-aicoding
```

### 5.3 公開直後に確認
- [ ] 上記 URL が 200
- [ ] アイコン / banner / categories / keywords が反映されている
- [ ] README が Marketplace の説明欄に綺麗にレンダリングされている
- [ ] CHANGELOG タブが表示されている
- [ ] 別マシン or VS Code 別プロファイルで `ext install yutakondo.vibeguard-aicoding` が通る

---

## 6. Open VSX Registry に公開（推奨）

VSCodium / code-server / Theia / Gitpod / Cursor の一部 利用者はここから落とす。

`ovsx` は `extensions/vscode/package.json` の devDep に既に入っているので、`npm install` 済みなら追加導入不要：

```bash
cd extensions/vscode
npx ovsx publish vibeguard-aicoding-0.1.0.vsix -p <openvsx_token>
```

確認：
```
https://open-vsx.org/extension/yutakondo/vibeguard-aicoding
```

> namespace `yutakondo` は GitHub ユーザー名と一致するので [open-vsx.org](https://open-vsx.org) の Settings → Namespaces で **Create Namespace** すればすぐ publish 可能（`open` 状態）。所有権を verified にしたい場合は別途 [eclipse/open-vsx.org の issue](https://github.com/EclipseFdn/open-vsx.org/issues) で Use case 1 のフォームで申請。

---

## 7. バージョン更新

```bash
cd extensions/vscode
npm run build -w vibeguard-aicoding

# パッチリリース (0.1.0 → 0.1.1)
npx vsce publish patch
# マイナー (0.1.0 → 0.2.0)
npx vsce publish minor

# あわせて Open VSX にも
npx ovsx publish -p <openvsx_token>
```

`vsce publish patch` は `package.json` の `version` を上げて自動で commit を作る。`CHANGELOG.md` を **先に** 更新しておくこと（公開順序：CHANGELOG 更新 → publish）。

---

## 8. 自動公開（任意・後で）

`.github/workflows/release-vscode.yml` を作って `v*` タグで自動公開できる。Secrets に：
- `VSCE_PAT` — Marketplace の PAT
- `OVSX_PAT` — Open VSX の PAT

を入れる。テンプレは Phase 4 で別途。

---

## 9. トラブルシュート

| 症状 | 対処 |
|---|---|
| `vsce package` で `Make sure to edit the README.md` | テンプレ文（`This is the README ...`）が残っている。VibeGuard 用の README に差し替える |
| `vsce package` で `Workspace dependencies are not supported` / 巨大な vsix （10 MB 超） / secret スキャナがテスト用トークンに反応 | `@vibeguard/*` が `node_modules` に symlink で居て vsce が親ディレクトリまで辿るのが原因。**必ず `--no-dependencies` を付ける**（§3.2 参照）。dist/extension.js は esbuild バンドル済みなので依存解決は不要 |
| `vsce publish` で `The extension '<name>' already exists in the Marketplace` | VS Code Marketplace の `name` はグローバル一意（publisher 違いでも衝突する）。`package.json` の `name` を変更する必要あり。npm workspace 名にもなっているので、ルートの `package.json` の build スクリプトと extensions/vscode/README の `npm -w ...` 参照も同時に更新 |
| `vsce publish` で `This extension display name is taken` | `displayName` も Marketplace 全体で一意制約あり（後出しの拡張は弾かれる）。`package.json` の `displayName` を変える。`name` は変えなくてよい（npm workspace 等に影響しない） |
| `vsce login` で `Personal Access Token verification failed` | PAT の `Organization` が「All accessible organizations」になっていない。再発行 |
| `vsce publish` で `ERROR Missing publisher name` | `package.json` の `publisher` が空 or プレースホルダ |
| `vsce publish` で `It seems the README.md still contains link(s) ...` | README 中の相対リンクがあると Marketplace では辿れない。GitHub の絶対 URL に直す（README は既に絶対 URL のみ）|
| Marketplace 上でアイコンが表示されない | `package.json` の `"icon": "icon.png"` が未指定、もしくは `.vscodeignore` で `icon.png` が弾かれている |
| インストール後に Diagnostics が出ない | `dist/extension.js` が bundle されていない（`npm run build -w vibeguard-aicoding` を流す前に publish した）。`vsce ls` で `.vsix` 中身を確認 |
| Open VSX に publish が拒否される | namespace が未予約。https://open-vsx.org の自分のページから namespace を発行（publisher と同じ ID にする）|

---

## 10. 参考

- [vsce CLI](https://github.com/microsoft/vscode-vsce)
- [Publishing Extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
- [Open VSX Publishing](https://github.com/EclipseFdn/open-vsx.org/wiki/Publishing-Extensions)
