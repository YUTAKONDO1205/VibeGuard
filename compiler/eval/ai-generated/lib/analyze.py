# -*- coding: utf-8 -*-
"""Round 2 tables."""
import json, os, collections, math, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, os.pardir, "data")
rows = json.load(open(os.path.join(OUT, "r2-build-rows.json"), encoding="utf-8"))
SCEN = json.load(open(os.path.join(ROOT, os.pardir, "scenarios.json"), encoding="utf-8"))
vg = {}
p_vg = os.path.join(OUT, "r2-vgmem006-before.json")
if os.path.exists(p_vg):
    vg = json.load(open(p_vg, encoding="utf-8"))

MODELS = ["haiku", "sonnet", "opus", "fable"]
FRAMINGS = ["N", "S", "E"]
FLABEL = {"N": "N 中立", "S": "S セキュア指示", "E": "E 性質を明示"}
VENDORS = ["clang-18", "gcc-13"]
OPTS = ["-O0", "-O1", "-O2", "-O3", "-Os"]


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


lines = []
def P(s=""):
    lines.append(s); print(s)


# per-file view (first row carries the file-level facts)
files = {}
for r in rows:
    files.setdefault(r["id"], r)
eras_f = {i: r for i, r in files.items() if r["fam"] == "erasure"}
authz_f = {i: r for i, r in files.items() if r["fam"] == "authz"}
cfg_f = {i: r for i, r in files.items() if r["fam"] == "configguard"}

scored = [r for r in rows if r.get("cc")]
er = [r for r in scored if r["kind"] == "erasure"]
# A configuration that did not compile has no verdict, and counting it in the
# denominator quietly turns "did not measure" into "measured no change" — the
# authz result is a rate of NOT changing, so a compile error would inflate it.
# The README says these are excluded; this is where that has to be true.
az = [r for r in scored if r["kind"] == "authz" and r["verdict"] != "COMPILE_ERROR"]
cf = [r for r in scored if r["kind"] == "configguard" and r["verdict"] != "COMPILE_ERROR"]
az_err = sum(1 for r in scored if r["kind"] == "authz" and r["verdict"] == "COMPILE_ERROR")
cf_err = sum(1 for r in scored if r["kind"] == "configguard" and r["verdict"] == "COMPILE_ERROR")

P("=" * 92)
P("AI 生成 C コードにおけるセキュリティ性質の消失   round 2")
P("生成 %d / ビルド判定 %d 構成" % (len(files), len(scored)))
P("=" * 92)
P("角括弧は Wilson 95%% 信頼区間。")

P()
P("## 計器の健全性")
P("  陽性対照 : %s" % dict(collections.Counter(r.get("control") for r in er)))
P("  対照の検出経路 : %s" % dict(collections.Counter(r.get("control_via") for r in er)))
P("  異常終了 : %s" % {k: v for k, v in collections.Counter(r["verdict"] for r in scored).items()
                     if k in ("COMPILE_ERROR", "NOT_OBSERVED", "ABLATION_DID_NOT_COMPILE", "VERIFICATION_INCOMPLETE")})
P("  目標関数の本体を特定できた : %d / %d" % (sum(1 for r in files.values() if r.get("scoped")), len(files)))

# ---------------- erasure ----------------
P()
P("=" * 92)
P("## erasure  (%d シナリオ / %d 生成)" % (10, len(eras_f)))
P("=" * 92)
P()
P("### RQ1  どのイディオムを書いたか")
P("%-16s %10s %14s %8s %10s   %s" % ("", "memset", "除去不能", "両方", "消去なし", "除去可能を選んだ割合"))
def idiom_of(r):
    return "none" if r["verdict"] == "NO_WIPE_WRITTEN" else r["idiom"]
for grp, label, keyf in (("framing", None, lambda r: r["framing"]), ("model", None, lambda r: r["model"])):
    keys = FRAMINGS if grp == "framing" else MODELS
    for k in keys:
        sub = [r for r in eras_f.values() if keyf(r) == k]
        c = collections.Counter(idiom_of(r) for r in sub)
        rem = c["removable"] + c["both"]
        P("%-16s %10d %14d %8d %10d   %s" % (FLABEL.get(k, k), c["removable"], c["nonremovable"], c["both"], c["none"],
                                             pct(rem, len(sub))))
    P()

P("### RQ2  最適化水準ごとの消失（両ベンダ合算、アブレーション判定）")
P("%-14s %s" % ("", "  ".join("%-11s" % o for o in OPTS)))
for idm in ("removable", "nonremovable", "both"):
    row = []
    for o in OPTS:
        sub = [r for r in er if r["opt"] == o and r.get("idiom") == idm]
        row.append("%3d/%-7d" % (sum(1 for r in sub if r["verdict"] == "WIPE_ELIMINATED"), len(sub)))
    P("%-14s %s" % (idm, "  ".join(row)))
P()
for cc in VENDORS:
    sub = [r for r in er if r["opt"] == "-O2" and r.get("idiom") in ("removable", "both") and r["cc"] == cc]
    P("  %-9s -O2 memset系 : %d / %d 除去  %s" % (cc, sum(1 for r in sub if r["verdict"] == "WIPE_ELIMINATED"), len(sub),
                                                pct(sum(1 for r in sub if r["verdict"] == "WIPE_ELIMINATED"), len(sub))))

P()
P("### 生成から成果物までの鎖  (-O2, erasure %d ファイル x 2 ベンダ)" % len(eras_f))
chain = collections.Counter()
for cc in VENDORS:
    for i, f in eras_f.items():
        if f["verdict"] == "NO_WIPE_WRITTEN":
            chain["A 消去を書かなかった"] += 1; continue
        rr = [r for r in er if r["id"] == i and r["cc"] == cc and r["opt"] == "-O2"]
        if not rr or rr[0]["verdict"] not in ("WIPE_ELIMINATED", "WIPE_SURVIVED"):
            chain["D 判定不能"] += 1
        elif rr[0]["verdict"] == "WIPE_ELIMINATED":
            chain["C 書いたが除去された"] += 1
        else:
            chain["B 書いて生き残った"] += 1
tot = sum(chain.values())
for k in ["A 消去を書かなかった", "B 書いて生き残った", "C 書いたが除去された", "D 判定不能"]:
    P("  %-26s %4d / %d  = %s" % (k, chain[k], tot, pct(chain[k], tot)))
bad = chain["A 消去を書かなかった"] + chain["C 書いたが除去された"]
P("  → 成果物に消去が無いと確認  %4d / %d  = %s" % (bad, tot, pct(bad, tot)))

P()
P("### 枠組み別「成果物に消去が無い」(-O2, 両ベンダ)")
for f in FRAMINGS:
    ids = [i for i, r in eras_f.items() if r["framing"] == f]
    A = sum(2 for i in ids if eras_f[i]["verdict"] == "NO_WIPE_WRITTEN")
    C = sum(1 for cc in VENDORS for i in ids
            for r in er if r["id"] == i and r["cc"] == cc and r["opt"] == "-O2" and r["verdict"] == "WIPE_ELIMINATED")
    P("  %-16s A=%3d C=%3d  → %3d / %3d  %s" % (FLABEL[f], A, C, A + C, len(ids) * 2, pct(A + C, len(ids) * 2)))
P()
P("### モデル別「成果物に消去が無い」(-O2, 両ベンダ)")
for m in MODELS:
    ids = [i for i, r in eras_f.items() if r["model"] == m]
    A = sum(2 for i in ids if eras_f[i]["verdict"] == "NO_WIPE_WRITTEN")
    C = sum(1 for cc in VENDORS for i in ids
            for r in er if r["id"] == i and r["cc"] == cc and r["opt"] == "-O2" and r["verdict"] == "WIPE_ELIMINATED")
    P("  %-16s A=%3d C=%3d  → %3d / %3d  %s" % (m, A, C, A + C, len(ids) * 2, pct(A + C, len(ids) * 2)))
P()
P("### シナリオ別「成果物に消去が無い」(-O2, 両ベンダ)")
for s in [k for k, v in SCEN.items() if v["fam"] == "erasure"]:
    ids = [i for i, r in eras_f.items() if r["scen"] == s]
    if not ids: continue
    A = sum(2 for i in ids if eras_f[i]["verdict"] == "NO_WIPE_WRITTEN")
    C = sum(1 for cc in VENDORS for i in ids
            for r in er if r["id"] == i and r["cc"] == cc and r["opt"] == "-O2" and r["verdict"] == "WIPE_ELIMINATED")
    P("  %-16s A=%3d C=%3d  → %3d / %3d  %s" % (s, A, C, A + C, len(ids) * 2, pct(A + C, len(ids) * 2)))

# ---------------- authz ----------------
P()
P("=" * 92)
P("## authz  (%d 生成 / 採点 %d 構成、COMPILE_ERROR %d を除外)  — 認可検査は -DNDEBUG を越えるか" % (len(authz_f), len(az), az_err))
P("=" * 92)
P()
na = sum(1 for r in authz_f.values() if r.get("uses_assert"))
P("  assert( を使ったファイル : %d / %d  %s" % (na, len(authz_f), pct(na, len(authz_f))))
if na:
    P("    枠組み別: %s" % dict(collections.Counter(r["framing"] for r in authz_f.values() if r.get("uses_assert"))))
    P("    モデル別: %s" % dict(collections.Counter(r["model"] for r in authz_f.values() if r.get("uses_assert"))))
ch = [r for r in az if r["verdict"] == "CHANGED_BY_NDEBUG"]
P("  -DNDEBUG で生成コードが変化した構成 : %d / %d  %s" % (len(ch), len(az), pct(len(ch), len(az))))
if ch:
    P("    該当ファイル: %s" % sorted({r["id"] for r in ch})[:12])

# ---------------- configguard ----------------
P()
P("=" * 92)
P("## configguard  (%d 生成 / 採点 %d 構成、COMPILE_ERROR %d を除外)  — 防御は構成に依存するか" % (len(cfg_f), len(cf), cf_err))
P("=" * 92)
P()
ng = sum(1 for r in cfg_f.values() if r.get("n_macros", 0) > 0)
P("  #if/#ifdef で防御を囲ったファイル : %d / %d  %s" % (ng, len(cfg_f), pct(ng, len(cfg_f))))
d = [r for r in cf if r["verdict"] == "DEFAULT_DIFFERS"]
same = [r for r in cf if r["verdict"] == "DEFAULT_EQUALS_ENABLED"]
nom = [r for r in cf if r["verdict"] == "NO_MACRO_GUARD"]
P("  既定ビルド ≠ 全マクロ定義ビルド : %d / %d  %s" % (len(d), len(cf), pct(len(d), len(cf))))
P("  既定ビルド = 全マクロ定義ビルド : %d" % len(same))
P("  マクロガード無し                : %d" % len(nom))
P()
P("  枠組み別に「防御が構成依存」= DEFAULT_DIFFERS のファイル数")
for f in FRAMINGS:
    ids = {r["id"] for r in d if r["framing"] == f}
    tot_ids = {i for i, r in cfg_f.items() if r["framing"] == f}
    P("    %-16s %2d / %2d  %s" % (FLABEL[f], len(ids), len(tot_ids), pct(len(ids), len(tot_ids))))

# ---------------- VG-MEM-006 ----------------
if vg:
    P()
    P("=" * 92)
    P("## VibeGuard VG-MEM-006 の追従性  (erasure %d ファイル)" % len(eras_f))
    P("=" * 92)
    rem_ids = {i for i, r in eras_f.items() if idiom_of(r) in ("removable", "both")}
    hit = set(vg)
    tp = len(rem_ids & hit); fn = len(rem_ids - hit); fp = len(hit - rem_ids)
    P("  除去可能な消去を書いたファイル : %d" % len(rem_ids))
    P("  うち VG-MEM-006 が検出         : %d   見逃し %d   （非該当への発火 %d）" % (tp, fn, fp))
    P("  再現率 : %s" % pct(tp, len(rem_ids)))
    if fn:
        P("  見逃しのシナリオ内訳: %s" % dict(collections.Counter(eras_f[i]["scen"] for i in (rem_ids - hit))))

open(os.path.join(OUT, "r2-results.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
