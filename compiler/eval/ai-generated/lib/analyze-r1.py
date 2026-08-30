# -*- coding: utf-8 -*-
"""Final tables. RQ2 is decided by ablation (C4), not by the zeroing count (C3).

C3 is kept only as the instrument-health record: it is what shows the oracle was
never blind (positive control PRESENT in 480/480), and it is what demonstrated,
on real generated code, the binding defect the paper declares in section 9.
"""
import json, os, collections, math

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, os.pardir, "data")
c1 = {r["id"]: r for r in json.load(open(os.path.join(OUT, "r1-lexical.json"), encoding="utf-8"))}
c2 = json.load(open(os.path.join(OUT, "r2-vgmem006-before.json"), encoding="utf-8"))
c3 = json.load(open(os.path.join(OUT, "r1-zeroing-oracle.json"), encoding="utf-8"))
c4 = json.load(open(os.path.join(OUT, "r1-ablation.json"), encoding="utf-8"))

MODELS = ["haiku", "sonnet", "opus", "fable"]
FRAMINGS = ["N", "S", "E"]
FLABEL = {"N": "N 中立", "S": "S セキュア指示", "E": "E 消去明示"}
VENDORS = ["clang-18", "gcc-13"]


def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pct(k, n):
    if n == 0: return "     n/a       "
    lo, hi = wilson(k, n)
    return "%5.1f%% [%4.1f-%4.1f]" % (100 * k / n, 100 * lo, 100 * hi)


ab = {}
for r in c4:
    if r.get("cc"):
        ab[(r["id"], r["cc"], r["opt"])] = r
ab_idiom = {r["id"]: r["idiom"] for r in c4}

lines = []
def P(s=""):
    lines.append(s); print(s)


P("=" * 86)
P("AI 生成 C コードにおける秘密消去イディオムと成果物までの生存")
P("n=120 生成 (4 モデル x 3 枠組み x 5 シナリオ x 2 反復)")
P("=" * 86)
P("角括弧は Wilson 95% 信頼区間。")

# ---- instrument health ----
P()
P("## 計器の健全性")
ctl3 = collections.Counter(r.get("control") for r in c3)
st3 = collections.Counter(r["state"] for r in c3)
ctl4 = collections.Counter(r.get("control") for r in c4 if r.get("cc"))
vd4 = collections.Counter(r["verdict"] for r in c4 if r.get("cc"))
P("  C3 ゼロ化オラクル : %d 構成、陽性対照 %s、COMPILE_ERROR %d、NOT_OBSERVED %d"
  % (len(c3), dict(ctl3), st3["COMPILE_ERROR"], st3["NOT_OBSERVED"]))
P("  C4 アブレーション : %d 構成、陽性対照 %s、COMPILE_ERROR %d、NOT_OBSERVED %d"
  % (sum(1 for r in c4 if r.get("cc")), dict(ctl4), vd4["COMPILE_ERROR"], vd4["NOT_OBSERVED"]))
P("  既知入力での検証  : デッドな memset は -O2 で本体バイト一致（除去）、")
P("                      読み取り後続の memset と explicit_bzero は全構成で生存。")

# ---- RQ1 ----
P()
P("## RQ1  モデルはどの消去イディオムを書いたか  (C1 字句分類, n=120)")
P()
P("%-18s %8s %10s %6s %6s   %s" % ("", "memset", "volatile", "両方", "消去なし", "除去可能を選んだ割合"))
for f in FRAMINGS:
    sub = [r for r in c1.values() if r["framing"] == f]
    c = collections.Counter(r["idiom"] for r in sub)
    P("%-18s %8d %10d %6d %6d   %s" % (FLABEL[f], c["REMOVABLE"], c["NON_REMOVABLE"], c["BOTH"], c["NONE"],
                                       pct(c["REMOVABLE"] + c["BOTH"], len(sub))))
P()
for m in MODELS:
    sub = [r for r in c1.values() if r["model"] == m]
    c = collections.Counter(r["idiom"] for r in sub)
    P("%-18s %8d %10d %6d %6d   %s" % (m, c["REMOVABLE"], c["NON_REMOVABLE"], c["BOTH"], c["NONE"],
                                       pct(c["REMOVABLE"] + c["BOTH"], len(sub))))
P()
nlib = sum(len(r["non_removable_calls"]) for r in c1.values())
nvol = sum(1 for r in c1.values() if r["volatile_loop"])
P("  除去不能側の実体 : volatile 手書き %d 件 / explicit_bzero・memset_s 等の標準 API %d 件" % (nvol, nlib))

# ---- RQ2 ----
P()
P("## RQ2  書いた消去は -O2 の成果物まで生き残るか  (C4 アブレーション)")
P()
P("判定 : 消去文を削除した版と削除しない版を同一フラグでビルドし、目標関数の本体を比較する。")
P("       一致 = 消去は何も生んでいない = WIPE_ELIMINATED。相違 = WIPE_SURVIVED。")
P("       束縛解析を必要としないので、論文 §9 が挙げる既知欠陥を回避している。")
P()
for opt in ("-O0", "-O2"):
    P("### %s" % opt)
    P("  %-9s %-18s %6s %8s   %s" % ("vendor", "イディオム", "母数", "消失", "消失率"))
    for cc in VENDORS:
        for idiom, lab in (("REMOVABLE", "memset"), ("VOLATILE_HELPER", "volatile ヘルパ"), ("BOTH", "両方")):
            rs = [r for (i, c, o), r in ab.items() if c == cc and o == opt and r["idiom"] == idiom]
            if not rs: continue
            lost = sum(1 for r in rs if r["verdict"] == "WIPE_ELIMINATED")
            P("  %-9s %-18s %6d %8d   %s" % (cc, lab, len(rs), lost, pct(lost, len(rs))))
    P()

P("### memset を書いたファイルの -O2 での消失（両ベンダ合算）")
rs = [r for (i, c, o), r in ab.items() if o == "-O2" and r["idiom"] in ("REMOVABLE", "BOTH")]
lost = sum(1 for r in rs if r["verdict"] == "WIPE_ELIMINATED")
P("  %d / %d = %s" % (lost, len(rs), pct(lost, len(rs))))
P()
P("### volatile ヘルパを書いたファイルの -O2 での消失（両ベンダ合算）")
rs = [r for (i, c, o), r in ab.items() if o == "-O2" and r["idiom"] == "VOLATILE_HELPER"]
lost = sum(1 for r in rs if r["verdict"] == "WIPE_ELIMINATED")
P("  %d / %d = %s" % (lost, len(rs), pct(lost, len(rs))))

# ---- chain ----
P()
P("## 生成から成果物までの鎖  (120 ファイル x 2 ベンダ = 240 機会, -O2)")
P()
chain = collections.Counter()
for cc in VENDORS:
    for fid, r in c1.items():
        if r["idiom"] == "NONE":
            chain["A 消去を書かなかった"] += 1; continue
        row = ab.get((fid, cc, "-O2"))
        if row is None:
            chain["D 検証不能（volatile 直書き）"] += 1
        elif row["verdict"] == "WIPE_ELIMINATED":
            chain["C 書いたが -O2 で除去された"] += 1
        elif row["verdict"] == "WIPE_SURVIVED":
            chain["B 書いて生き残った"] += 1
        else:
            chain["D 検証不能（volatile 直書き）"] += 1
tot = sum(chain.values())
for k in ["A 消去を書かなかった", "B 書いて生き残った", "C 書いたが -O2 で除去された", "D 検証不能（volatile 直書き）"]:
    P("  %-34s %4d / %d  = %s" % (k, chain[k], tot, pct(chain[k], tot)))
P()
bad = chain["A 消去を書かなかった"] + chain["C 書いたが -O2 で除去された"]
P("  → 成果物に秘密消去が無いと確認できた   %4d / %d = %s" % (bad, tot, pct(bad, tot)))
P("     （D の %d 機会は判定していない。上の数字は下限である。）" % chain["D 検証不能（volatile 直書き）"])

P()
P("### C（書いたのに除去された）の枠組み別  -O2, 両ベンダ")
for f in FRAMINGS:
    ids = [i for i, r in c1.items() if r["framing"] == f]
    n_c = sum(1 for cc in VENDORS for i in ids
              if ab.get((i, cc, "-O2")) and ab[(i, cc, "-O2")]["verdict"] == "WIPE_ELIMINATED")
    n_d = sum(1 for cc in VENDORS for i in ids if ab.get((i, cc, "-O2")))
    P("  %-18s %2d / %2d 判定済み   %s" % (FLABEL[f], n_c, n_d, pct(n_c, n_d)))

P()
P("### C の モデル別  -O2, 両ベンダ")
for m in MODELS:
    ids = [i for i, r in c1.items() if r["model"] == m]
    n_c = sum(1 for cc in VENDORS for i in ids
              if ab.get((i, cc, "-O2")) and ab[(i, cc, "-O2")]["verdict"] == "WIPE_ELIMINATED")
    n_d = sum(1 for cc in VENDORS for i in ids if ab.get((i, cc, "-O2")))
    n_none = sum(1 for i in ids if c1[i]["idiom"] == "NONE") * 2
    n_opp = len(ids) * 2
    P("  %-8s 除去された %2d / %2d 判定済み   消去なし %2d/%d   %s" % (m, n_c, n_d, n_none, n_opp, pct(n_c, n_d) if n_d else ""))

# ---- C2 ----
P()
P("## 副産物  VibeGuard VG-MEM-006 の取りこぼし  (C1 vs C2, n=120)")
miss = [fid for fid, r in c1.items() if r["idiom"] in ("REMOVABLE", "BOTH") and fid not in c2]
extra = [fid for fid in c2 if c1[fid]["idiom"] not in ("REMOVABLE", "BOTH")]
P("  一致 %d/120 = %.1f%%   見逃し %d   過検出 %d" % (120 - len(miss) - len(extra), 100 * (120 - len(miss) - len(extra)) / 120, len(miss), len(extra)))
P("  見逃しの内訳: %s" % dict(collections.Counter(c1[f]["scenario"] for f in miss)))

open(os.path.join(OUT, "r1-results.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
