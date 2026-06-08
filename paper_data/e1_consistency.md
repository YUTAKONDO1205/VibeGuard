# E1 — cross-channel judgment consistency (paper item ②)

Built node entry (`scanPath`, used by CLI + GitHub Action) vs built browser
entry (`scan`, used by Chrome + VS Code) over identical inputs. A divergence
is any finding tuple present on one path but not the other.

| channel | entry point (built artifact) |
|---|---|
| Chrome / VS Code | `@vibeguard/analyzer-core/browser` → `dist/browser.js` (`scan`) |
| CLI / GitHub Action | `@vibeguard/analyzer-core` → `dist/index.js` (`scanPath`) |

| corpus | files | findings (node) | findings (browser) | divergences |
|---|---|---|---|---|
| samples/vulnerable | 13 | 50 | 50 | 0 |
| test_problem | 1 | 20 | 20 | 0 |

**Result: 0 divergences — node and browser paths are byte-identical on the detection tuple. ✓**
