# VibeGuard 論文 実測データサマリ (取得日 2026-06-06)

tool version 0.1.3 / ENGINE_VERSION 0.1.0 / Node 24 / vitest tests: CLI 25 + Chrome 13 = all pass
ルール総数: 47 (VG-INJ 19, VG-QUAL 10, VG-AUTH 7, VG-SEC 4, VG-FW 4, VG-CRYPTO 3)
対応言語: JS, TS, Python, Go, Java, Ruby, PHP, C# (8言語)

## E2 samples/vulnerable (13ファイル/6言語)
- total 50 findings
- severity: critical 5 / high 15 / medium 27 / low 3
- confidence: high 6 / medium 26 / low 18
- category: injection 7, secrets 5, crypto 15, auth 4, access-control 2, config 1, quality 1, ai-quality 15
- exec 23ms
- per-language: javascript 23, python 15, php 4, csharp 3, ruby 3, go 2

## E3 samples/safe (4ファイル)
- total 0 findings (false positive = 0)
- exec 10ms

## test_problem.py (単一ファイルデモ)
- total 20 findings: critical 5 / high 5 / medium 8 / low 2
- category: injection 5, ai-quality 6, crypto 3, config 2, secrets 1, auth 1, logging 1, quality 1

## E4 PR差分スキャン (baseline 38 findings / 10ファイル)
| シナリオ | 全体 | 変更ファイル | diff | 削減率(全体比) | 追加行検出保持 |
|---|---|---|---|---|---|
| A 新規ファイルに脆弱コード追加 | 39 | 1 | 1 | 97.4% | 1/1 |
| B 既存脆弱ファイルに安全行のみ追加 | 38 | 2 | 0 | 100% | 0/0 |
| C 既存安全ファイルに脆弱行追加 | 39 | 1 | 1 | 97.4% | 1/1 |
A: 追加eval()行をVG-INJ-004(critical)で検出・保持。Bは既存2件を追加行外として除外。

## E5 性能 (3回のmedian, プロセス実行時間, ms)
| ワークロード | モード | median | max | target | 判定 |
|---|---|---|---|---|---|
| 単一ファイル | fast | 73.2 | 74.3 | ≤3000 | ok |
| samples/vulnerable | standard | 89.8 | 89.9 | ≤1000 | ok |
| repo全体(ignore付) | standard | 224.9 | 250.1 | ≤300000 | ok |

## E1 一貫性
4導線(VS Code/Chrome/CLI/GitHub Actions)は同一 analyzer-core パッケージに依存(依存グラフ上で単一)。
→ 同一入力に対しruleId/severity/categoryは構成上一致。UI表現(行表示・配色)のみ導線で差異。
