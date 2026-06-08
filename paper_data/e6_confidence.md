# E6 — context-window confidence (paper item ①)

## paper_data/e6repo — control vs treatment

| ruleId | location | sev | context signal | before → after |
|---|---|---|---|---|
| VG-FW-001 | debug_in_docstring.py:9 | high | docstring | **medium → low** |
| VG-QUAL-008 | debug_in_docstring.py:9 | medium | docstring | **medium → low** |
| VG-FW-002 | debug_in_docstring.py:10 | critical | docstring | **high → low** |
| VG-FW-001 | debug_in_docstring.py:18 | high | — (executable) | medium → medium |
| VG-QUAL-008 | debug_in_docstring.py:18 | medium | — (executable) | medium → medium |
| VG-INJ-004 | eval_in_block_comment.js:9 | critical | docstring | **high → low** |
| VG-INJ-004 | eval_in_block_comment.js:14 | critical | — (executable) | high → high |
| VG-AUTH-004 | tls_client.py:8 | high | — (executable) | high → high |
| VG-AUTH-004 | tls_client.test.py:11 | high | test-path | **high → medium** |

- findings: **9**  ·  down-ranked (treatment): **5**  ·  unchanged (control/executable): **4**
- confidence after ①: {"high":2,"medium":3,"low":4}

## samples/vulnerable — no-collateral check

- findings: **50** (engine E2 baseline: 50)
- confidence after ①: {"high":6,"medium":26,"low":18} (E2 baseline: {"high":6,"medium":26,"low":18})
- true-positives down-ranked: **0** ✓ (no collateral damage)

## samples/safe — false-positive guard

- findings: **0** (gate: must be 0) ✓
