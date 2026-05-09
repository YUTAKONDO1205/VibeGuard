# Runbook: Publish VibeGuard Action to GitHub Marketplace

リポジトリルートの [`action.yml`](../../action.yml) を GitHub Marketplace の Action としてリリースするための手順。

> **前提**：リポジトリは public（private は Marketplace 不可）、`action.yml` は **リポジトリのルート** に存在、`name:` がほかの Marketplace Action と衝突しないこと。

---

## 1. 公開前チェック

### 1.1 `action.yml` の検証
- [`action.yml`](../../action.yml) がルートにある
- `name`, `description`, `branding` が埋まっている（Marketplace の検証で必須）
- `branding.icon` は [Feather Icons](https://feathericons.com/) のセットから選ぶ（現在は `shield`）
- `branding.color` は `white | yellow | blue | green | orange | red | purple | gray-dark` のいずれか

### 1.2 アクション動作確認
- ブランチ上で [`.github/workflows/action-smoke-test.yml`](../../.github/workflows/action-smoke-test.yml) が緑になっていること
- 自前 push もしくは PR で `Action Smoke Test` ワークフローが PASS したことを確認

### 1.3 README に Marketplace バッジ用の余地を作っておく
公開後、Marketplace から発行される URL（`https://github.com/marketplace/actions/<slug>`）を README に追記する。

---

## 2. リリースタグの作成

Marketplace 公開は **Release ベース** で行う。タグだけでは公開されない。

```bash
# 例: v0.1.0 を切る
git checkout main
git pull
git tag v0.1.0
git push origin v0.1.0
```

GitHub の Releases ページから「Draft a new release」を選び、タグ `v0.1.0` を選択する。

---

## 3. Marketplace 公開チェックボックス

Release のドラフト画面で：

1. 上部の **「Publish this Action to the GitHub Marketplace」** をチェック
2. **Primary Category** を選ぶ（推奨：`Code review` または `Security`）
3. **Secondary Category**（任意）：もう一つ選べる場合は反対側
4. ライセンス警告が出る場合は LICENSE ファイルを追加してから再アップ
5. **Release title**：`VibeGuard v0.1.0` 等
6. **Release notes**：何が入ったか箇条書き（[CHANGELOG.md](../../CHANGELOG.md) があるならそこからコピペ）
7. **Set as the latest release** にチェック
8. **Publish release** を押す

公開後、`https://github.com/marketplace/actions/vibeguard` に出る（slug は `name:` から自動生成、衝突したら自動でサフィックス付与）。

---

## 4. メジャー版タグの運用

ベストプラクティスとして、**メジャー版を移動タグ** で運用すると、利用者は `uses: YUTAKONDO1205/VibeGuard@v0` と書ける。

```bash
# v0.1.0 を切ったあとで
git tag -fa v0 -m "v0 → v0.1.0"
git push origin v0 --force
```

注意：
- `--force` はメジャー版タグだけに使う。バージョン固定タグ（`v0.1.0`）は移動させない
- 利用者には `@v0` 系を推奨し、`@main` は禁止する旨を README に書く
- 互換性の壊れる変更があるときは `v1` に切る

---

## 5. 利用者側の使い方（README に書く想定の例）

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0   # diff scan を使うときだけ必要
- uses: YUTAKONDO1205/VibeGuard@v0
  with:
    path: .
    mode: standard
    format: sarif
    out: vibeguard.sarif
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vibeguard.sarif
    category: vibeguard
```

PR 差分のみスキャンしたい場合：

```yaml
- uses: YUTAKONDO1205/VibeGuard@v0
  with:
    diff: origin/${{ github.base_ref }}...HEAD
    format: markdown
    out: report.md
    fail-on: high
```

---

## 6. リリース後の確認

- [ ] `https://github.com/marketplace/actions/<slug>` が 200 を返す
- [ ] Marketplace ページに icon / branding 色が反映されている
- [ ] 別の検証用リポジトリで `uses: YUTAKONDO1205/VibeGuard@v0.1.0` を呼んで通ること
- [ ] README に Marketplace バッジ＋利用例を反映（PR を別途立てる）

---

## 7. トラブルシュート

| 症状 | 対処 |
|---|---|
| Release 作成画面に Marketplace チェックが出ない | リポジトリが private、`action.yml` がルートにない、`branding.icon/color` が無効 |
| 「The icon is not valid」 | Feather Icons の名前を使う（`shield`, `eye`, `bug` など） |
| 「Action name conflict」 | `action.yml` の `name:` を変更（例：`VibeGuard Security`） |
| 利用者側で `npm ci` が失敗 | `package-lock.json` がリポジトリに含まれているか確認。Marketplace 経由でも action_path には lockfile が必要 |
| 利用者側で `--diff` が空のスキャンになる | 利用者の workflow が `actions/checkout@v4` で `fetch-depth: 0` を指定していない |
