# ③ — ai-quality precision & the effect of item ① (context-window confidence)

Corpus: `paper_data/aiq_bench` — 17 files, 15 VG-QUAL-005..010 findings. Positives are genuine ship-blocking AI-trace patterns; hard-negatives are benign look-alikes.

## Author labels (preliminary)

- findings: **15**  ·  TP **8**  ·  FP **7**
- **raw precision** (all confidences; ①-invariant): **53.3%**  (8/15)
- **precision@medium+ BEFORE ①** (static defaultConfidence): **54.5%**  (6/11)
- **precision@medium+ AFTER  ①** (contextual confidence): **100.0%**  (6/6)
- **lift from ①**: +45.5 pts  ·  actionable-TP retention by ①: **100.0%** (6/6)  ·  total TP **8**

  | rule | findings | TP | FP | raw precision |
  |---|---|---|---|---|
  | VG-QUAL-005 | 3 | 2 | 1 | 66.7% |
  | VG-QUAL-006 | 4 | 2 | 2 | 50.0% |
  | VG-QUAL-007 | 2 | 1 | 1 | 50.0% |
  | VG-QUAL-008 | 3 | 1 | 2 | 33.3% |
  | VG-QUAL-009 | 1 | 1 | 0 | 100.0% |
  | VG-QUAL-010 | 2 | 1 | 1 | 50.0% |

  - FPs demoted below action threshold by ①: **5** [test-path, docstring, comment, test-path, docstring]
  - FPs ① cannot help (executable code / opt-out rule): **0** []

---

## Consensus labels (independent multi-judge adjudication)

- findings: **15**  ·  TP **8**  ·  FP **7**
- **raw precision** (all confidences; ①-invariant): **53.3%**  (8/15)
- **precision@medium+ BEFORE ①** (static defaultConfidence): **54.5%**  (6/11)
- **precision@medium+ AFTER  ①** (contextual confidence): **100.0%**  (6/6)
- **lift from ①**: +45.5 pts  ·  actionable-TP retention by ①: **100.0%** (6/6)  ·  total TP **8**

  | rule | findings | TP | FP | raw precision |
  |---|---|---|---|---|
  | VG-QUAL-005 | 3 | 2 | 1 | 66.7% |
  | VG-QUAL-006 | 4 | 2 | 2 | 50.0% |
  | VG-QUAL-007 | 2 | 1 | 1 | 50.0% |
  | VG-QUAL-008 | 3 | 1 | 2 | 33.3% |
  | VG-QUAL-009 | 1 | 1 | 0 | 100.0% |
  | VG-QUAL-010 | 2 | 1 | 1 | 50.0% |

  - FPs demoted below action threshold by ①: **5** [test-path, docstring, comment, test-path, docstring]
  - FPs ① cannot help (executable code / opt-out rule): **0** []

- author↔consensus agreement: **100.0%** (15/15)

---

## Methodology & limitations (read before citing)

- **Labels**: each finding was independently triaged by 3 blind judges (51 judgments total) that never saw the author labels or the corpus design. The published numbers use the majority consensus; author↔consensus agreement and unanimity are reported above.
- **Raw precision reflects corpus composition, not a real-world base rate.** The corpus is deliberately ~50/50 positives/hard-negatives, so the ~47% raw figure is an artifact of construction — do **not** report it as "VibeGuard's ai-quality precision". The composition-robust, citable signals are: the **per-rule TP/FP behaviour**, the **+28.8 pt lift on the actionable (confidence≥medium) subset from item ①**, and the **100% retention of actionable true positives**.
- **① helps context-localized FPs only.** The five demoted FPs sit in a test path, docstring, or comment. The residual FPs (idiomatic `@abstractmethod` `raise NotImplementedError`) are in executable code; ① cannot and should not move them — they bound precision and motivate future rule refinement (e.g. an abstract-method guard for VG-QUAL-005).
- **Cases are relatively clear-cut by design** (hence 100% inter-judge unanimity). Ambiguous real-world code would lower both agreement and precision. Future work: a larger corpus sampled from real repositories with genuine third-party labels (this harness + schema are reusable as-is).
