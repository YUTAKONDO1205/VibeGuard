# ④ — SAST baseline: VibeGuard ∩ Bandit over `samples/vulnerable (Python)`

Baseline: **Bandit** (Python AST SAST; comparison scoped to .py files). VibeGuard is pure-regex — this is a complementarity map, not a precision race.

| partition | count | meaning |
|---|---|---|
| both (overlap) | 12 | locations flagged by VibeGuard **and** Bandit — the obvious vulns VibeGuard does not miss |
| VibeGuard-only | 3 | flagged by VibeGuard, not Bandit (incl. VibeGuard's ai-quality niche) |
| Bandit-only | 2 | deeper AST/dataflow Bandit catches that VibeGuard's regex misses |
| VibeGuard total (.py) | 15 | |
| Bandit total | 13 | |

## VibeGuard's niche — ai-quality / SATD findings

- VibeGuard ai-quality (category=ai-quality, the AI-trace heuristics) findings: **3**
- of those, co-located with any Bandit finding: **2** → **33%** are unique to VibeGuard (Bandit's rules target code-security bugs, not self-admitted-technical-debt / AI-trace patterns).

## What Bandit catches that VibeGuard misses (honest ceiling)

| file:line | Bandit check | cwe |
|---|---|---|
| command_injection.py:2 | B404 blacklist | CWE-78 |
| django_settings.py:10 | B105 hardcoded_password_string | CWE-259 |

## Partition by VibeGuard category (overlap vs unique)

| category | total | overlap w/ Bandit | VibeGuard-only |
|---|---|---|---|
| access-control | 1 | 0 | 1 |
| ai-quality | 3 | 2 | 1 |
| auth | 2 | 1 | 1 |
| config | 1 | 1 | 0 |
| crypto | 1 | 1 | 0 |
| injection | 5 | 5 | 0 |
| quality | 1 | 1 | 0 |
| secrets | 1 | 1 | 0 |

# ④ — SAST baseline: VibeGuard ∩ Bandit over `paper_data/aiq_bench (Python, ai-quality niche)`

Baseline: **Bandit** (Python AST SAST; comparison scoped to .py files). VibeGuard is pure-regex — this is a complementarity map, not a precision race.

| partition | count | meaning |
|---|---|---|
| both (overlap) | 0 | locations flagged by VibeGuard **and** Bandit — the obvious vulns VibeGuard does not miss |
| VibeGuard-only | 7 | flagged by VibeGuard, not Bandit (incl. VibeGuard's ai-quality niche) |
| Bandit-only | 0 | deeper AST/dataflow Bandit catches that VibeGuard's regex misses |
| VibeGuard total (.py) | 7 | |
| Bandit total | 0 | |

## VibeGuard's niche — ai-quality / SATD findings

- VibeGuard ai-quality (category=ai-quality, the AI-trace heuristics) findings: **5**
- of those, co-located with any Bandit finding: **0** → **100%** are unique to VibeGuard (Bandit's rules target code-security bugs, not self-admitted-technical-debt / AI-trace patterns).

## What Bandit catches that VibeGuard misses (honest ceiling)

- none in this corpus at the chosen ruleset.

## Partition by VibeGuard category (overlap vs unique)

| category | total | overlap w/ Bandit | VibeGuard-only |
|---|---|---|---|
| ai-quality | 5 | 0 | 5 |
| config | 2 | 0 | 2 |

---

## Methodology & limitations (read before citing)

- **Baseline tool**: Bandit 1.9.4 (pure-Python AST SAST). Semgrep has no Windows-native build and the Docker daemon was unreachable here; `scripts/sast-baseline-eval.mjs` ingests `semgrep --json` unchanged — `scripts/run-semgrep.sh` reproduces multi-language on Linux/CI.
- **Scope = Python only** (Bandit's only language); co-location match = same file, line +/-2. Not a precision/recall verdict — a coverage/complementarity map. The honest signals are the Bandit-only column (VibeGuard's regex ceiling) and the ai-quality VibeGuard-only column (its differentiator).
- The ai-quality "overlap" in the real-vuln corpus is coincidental line-proximity, not Bandit detecting the SATD pattern; the isolated niche corpus shows the true 0-overlap picture.
