# -*- coding: utf-8 -*-
"""Generate Fig1 (architecture) and Fig2 (PR-diff flow) for the VibeGuard paper.
Monochrome, English labels (matches template figure conventions), high DPI."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5})

EDGE = "#222222"
FILL = "#ffffff"
ENGINE = "#e8e8e8"

def box(ax, x, y, w, h, text, fill=FILL, fs=8.5, bold=False):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                       linewidth=1.1, edgecolor=EDGE, facecolor=fill)
    ax.add_patch(p)
    ax.text(x + w/2, y + h/2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", linespacing=1.25)

def arrow(ax, x1, y1, x2, y2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                 mutation_scale=11, linewidth=1.1, color=EDGE,
                 shrinkA=1, shrinkB=1))

# ---------------- Figure 1: architecture ----------------
# Larger, less-cluttered: bold box titles + a single short subtitle each
# (detailed internals are described in the body text, not crammed into the figure).
def box2(ax, x, y, w, h, title, sub=None, fill=FILL, tfs=11.0, sfs=8.8):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                       linewidth=1.2, edgecolor=EDGE, facecolor=fill)
    ax.add_patch(p)
    cx = x + w/2
    if sub:
        ax.text(cx, y + h*0.63, title, ha="center", va="center", fontsize=tfs, fontweight="bold")
        ax.text(cx, y + h*0.28, sub, ha="center", va="center", fontsize=sfs, color="#333333")
    else:
        ax.text(cx, y + h/2, title, ha="center", va="center", fontsize=tfs, fontweight="bold")

fig, ax = plt.subplots(figsize=(4.8, 4.05))
ax.set_xlim(0, 10); ax.set_ylim(0, 10.2); ax.axis("off")

clients = [
    (0.10, "VS Code", "while writing"),
    (2.58, "Chrome", "while reading"),
    (5.06, "CLI", "local / CI"),
    (7.54, "GitHub Actions", "before merge"),
]
cw, ch, cy = 2.36, 1.22, 8.8
for cx, title, sub in clients:
    box2(ax, cx, cy, cw, ch, title, sub, tfs=8.6, sfs=8.0)
    arrow(ax, cx + cw/2, cy, cx + cw/2, 7.95)

box2(ax, 1.1, 6.65, 7.8, 1.25, "analyzer-core", "shared analysis engine", fill=ENGINE, tfs=12.0, sfs=9.2)
arrow(ax, 5.0, 6.65, 5.0, 6.05)

box2(ax, 1.1, 4.9, 7.8, 1.15, "rules", "7 categories, incl. ai-quality", tfs=11.5, sfs=9.2)
arrow(ax, 5.0, 4.9, 5.0, 4.3)

box2(ax, 1.1, 3.1, 7.8, 1.2, "findings-schema", "unified Finding (severity / confidence / ...)", tfs=11.5, sfs=9.0)
arrow(ax, 3.2, 3.1, 2.5, 2.05)
arrow(ax, 6.8, 3.1, 7.5, 2.05)

box2(ax, 0.35, 0.9, 4.3, 1.15, "remediation-engine", "why / how / fix", tfs=9.8, sfs=8.7)
box2(ax, 5.35, 0.9, 4.3, 1.15, "sarif-adapter / formatters", "SARIF / Markdown / JSON", tfs=8.9, sfs=8.7)

fig.tight_layout(pad=0.3)
fig.savefig("paper_data/fig1_architecture.png", dpi=300, bbox_inches="tight")
plt.close(fig)

# ---------------- Figure 2: PR-diff flow ----------------
fig, ax = plt.subplots(figsize=(4.4, 5.6))
ax.set_xlim(0, 10); ax.set_ylim(0, 12.4); ax.axis("off")

steps = [
    "git diff --unified=0",
    "changed files + added line numbers",
    "read each changed file in full",
    "run analyzer-core on the full file",
    "keep only findings overlapping added lines",
    "Markdown PR comment / fail gate",
]
bw, bh = 8.4, 1.35
x0 = 0.8
ys = [10.7, 8.75, 6.8, 4.85, 2.9, 0.95]
emph = {3, 4}  # highlight the context-preserving core
for i, (s, y) in enumerate(zip(steps, ys)):
    box(ax, x0, y, bw, bh, s, fill=(ENGINE if i in emph else FILL),
        bold=(i in emph), fs=8.4)
    if i < len(steps) - 1:
        arrow(ax, x0 + bw/2, y, x0 + bw/2, ys[i+1] + bh)

fig.tight_layout(pad=0.3)
fig.savefig("paper_data/fig2_prdiff.png", dpi=300, bbox_inches="tight")
plt.close(fig)
print("figures written")
