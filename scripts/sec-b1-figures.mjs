// Figure generator for the evasion measurements — reads the result JSON and
// emits SVG, so no number in a figure is ever typed by hand.
//
// Two figures, because there are two questions:
//
//   1. Per transform, does normalization shrink evasion? (rate under each arm,
//      plus the difference). Diverging, because the difference has a SIGN: a
//      normalization pass can in principle lose a detection it used to make.
//      Every cell landing on the neutral-or-blue side is the result, not the
//      palette being tidy — it is the same fact the paired test reports as
//      "no discordant pair in the losing direction".
//
//   2. Per transform, does the effect carry across tools? A lexical matcher and
//      an AST one are the two readings being compared; this is the axis that
//      makes "lexical matchers evade more easily" a measurement rather than an
//      assertion.
//
// DENOMINATORS ARE SMALL and the figures say so on their face. Per-cell counts
// run to single digits, where one flip moves a rate by a third. Cells are
// therefore annotated with n, cells with no observations are drawn as absent
// rather than as zero (a zero rate and no data are not the same claim), and the
// caption states the range. A reader who wants to weigh a cell can, which is the
// whole reason n is on the tile instead of in a footnote.
//
// Dependency-free by construction: SVG is written as text. A companion Markdown
// table carries the same numbers for anyone who cannot use the colour channel.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const RESULTS = join(ROOT, 'security-experiment/_results');
const OUT = join(RESULTS, 'figures');

// Steps come from the reference palette. Sequential is one hue, light to dark;
// diverging is two hues that read as opposite around a neutral. Both ramps are
// monotonic in lightness so they survive greyscale printing, and neither is a
// rainbow — hue never encodes magnitude here, only sign.
const BLUE = ['#cde2fb', '#b7d3f6', '#9ec5f4', '#86b6ef', '#6da7ec', '#5598e7', '#3987e5', '#2a78d6', '#256abf', '#1c5cab', '#184f95', '#104281', '#0d366b'];
const RED = ['#fbd8d7', '#f6bfbe', '#f0a3a2', '#e98583', '#e66767', '#e34948', '#d24140', '#c93b3a', '#a83130', '#8a2827', '#6b1f1e'];
const NEUTRAL = '#f0efec';

const INK = '#0b0b0b';
const INK_2 = '#52514e';
const MUTED = '#898781';
const SURFACE = '#fcfcfb';
const HAIRLINE = '#e1e0d9';

const CELL = 46;
const ROW = 30;
const HEAD_H = 78;
const PAD = 16;
const N_COL_W = 52;

// Rough advance widths. There is no text-measuring API here and adding one
// would mean a dependency, so the canvas is sized from an estimate that
// deliberately runs WIDE: over-estimating costs a little whitespace, while
// under-estimating clips a label off the edge of the figure.
const textW = (s, px) => String(s).length * px * 0.56;

/** Greedy wrap so a long caption never runs past the canvas it is sized for. */
function wrap(line, px, maxW) {
  const out = [];
  let cur = '';
  for (const word of String(line).split(' ')) {
    const next = cur ? `${cur} ${word}` : word;
    if (cur && textW(next, px) > maxW) {
      out.push(cur);
      cur = word;
    } else {
      cur = next;
    }
  }
  if (cur) out.push(cur);
  return out;
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Sequential: magnitude only. `null` means no observations, never zero. */
function seqFill(v) {
  if (v == null) return null;
  return BLUE[Math.min(BLUE.length - 1, Math.round(v * (BLUE.length - 1)))];
}

/** Diverging: sign picks the arm, magnitude picks the step, zero is neutral. */
function divFill(v) {
  if (v == null) return null;
  if (Math.abs(v) < 1e-9) return NEUTRAL;
  const ramp = v > 0 ? BLUE : RED;
  const mid = Math.ceil(ramp.length / 2);
  return ramp[Math.min(ramp.length - 1, mid + Math.round(Math.abs(v) * (ramp.length - 1 - mid)))];
}

/** Ink that stays legible on the tile it sits on, so values are never colour-only. */
function inkOn(fill) {
  if (fill == null) return MUTED;
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(fill.slice(i, i + 2), 16) / 255);
  const lin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b) > 0.42 ? INK : '#ffffff';
}

function heatmap({ title, subtitle, caption, columns, rows, legend }) {
  const labelW = Math.ceil(Math.max(...rows.map((r) => textW(r.negativeControl ? `${r.label} †` : r.label, 11)))) + 22;
  const gridW = labelW + columns.length * CELL + N_COL_W;
  // The prose is usually wider than the grid, so it sizes the canvas too.
  const proseW = Math.max(textW(title, 14), textW(subtitle, 11), textW(legend, 10));
  const w = Math.ceil(Math.max(gridW, Math.min(proseW, 900)) + PAD * 2);
  const textMax = w - PAD * 2;
  const legendLines = wrap(legend, 10, textMax);
  const captionLines = caption.flatMap((c) => wrap(c, 9.5, textMax));
  const h = HEAD_H + rows.length * ROW + 26 + (legendLines.length + captionLines.length) * 14 + PAD;
  const p = [];

  p.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" font-family="system-ui, -apple-system, Segoe UI, sans-serif">`);
  p.push(`<rect width="${w}" height="${h}" fill="${SURFACE}"/>`);
  p.push(`<text x="${PAD}" y="24" font-size="14" font-weight="600" fill="${INK}">${esc(title)}</text>`);
  for (const [i, line] of wrap(subtitle, 11, textMax).entries()) {
    p.push(`<text x="${PAD}" y="${42 + i * 14}" font-size="11" fill="${INK_2}">${esc(line)}</text>`);
  }

  columns.forEach((c, i) => {
    const x = labelW + i * CELL + CELL / 2;
    p.push(`<text x="${x}" y="${HEAD_H - 8}" font-size="10" fill="${MUTED}" text-anchor="middle">${esc(c.label)}</text>`);
  });

  rows.forEach((row, r) => {
    const y = HEAD_H + r * ROW;
    const name = row.negativeControl ? `${row.label} †` : row.label;
    p.push(`<text x="${labelW - 10}" y="${y + ROW / 2 + 4}" font-size="11" fill="${INK_2}" text-anchor="end">${esc(name)}</text>`);

    row.cells.forEach((cell, i) => {
      const x = labelW + i * CELL;
      const fill = columns[i].diverging ? divFill(cell.value) : seqFill(cell.value);
      if (fill == null) {
        // Absent, not zero. Drawn as a hairline outline with a dash so it reads
        // as "nothing observed" in colour, in greyscale and in print alike.
        p.push(`<rect x="${x + 1}" y="${y + 1}" width="${CELL - 2}" height="${ROW - 2}" rx="4" fill="none" stroke="${HAIRLINE}"/>`);
        p.push(`<text x="${x + CELL / 2}" y="${y + ROW / 2 + 4}" font-size="10" fill="${MUTED}" text-anchor="middle">–</text>`);
        return;
      }
      // The 2px inset is the surface gap that keeps adjacent tiles from fusing.
      p.push(`<rect x="${x + 1}" y="${y + 1}" width="${CELL - 2}" height="${ROW - 2}" rx="4" fill="${fill}"/>`);
      p.push(`<text x="${x + CELL / 2}" y="${y + ROW / 2 + 3.5}" font-size="10" fill="${inkOn(fill)}" text-anchor="middle">${esc(cell.text)}</text>`);
    });

    p.push(`<text x="${labelW + columns.length * CELL + 8}" y="${y + ROW / 2 + 4}" font-size="9" fill="${MUTED}">n=${row.n}</text>`);
  });

  let ly = HEAD_H + rows.length * ROW + 22;
  for (const line of legendLines) {
    p.push(`<text x="${PAD}" y="${ly}" font-size="10" fill="${INK_2}">${esc(line)}</text>`);
    ly += 14;
  }
  for (const line of captionLines) {
    p.push(`<text x="${PAD}" y="${ly}" font-size="9.5" fill="${MUTED}">${esc(line)}</text>`);
    ly += 14;
  }
  p.push('</svg>');
  return p.join('\n');
}

const pct = (v) => (v == null ? '–' : v === 0 ? '0' : v.toFixed(2).replace(/^0/, ''));

// ---------------------------------------------------------------- figure 1
const er = JSON.parse(readFileSync(join(RESULTS, 'b1-er-eval.json'), 'utf8'));

const armRows = Object.entries(er.byTransform)
  .map(([id, t]) => {
    const e = t.paired.exists;
    return {
      label: `${id} ${t.name}`,
      negativeControl: Boolean(t.negativeControl),
      n: e.false.denominator,
      predicted: t.d2Predicted,
      cells: [
        { value: e.false.er, text: pct(e.false.er) },
        { value: e.true.er, text: pct(e.true.er) },
        { value: e.deltaEr, text: pct(e.deltaEr) },
      ],
    };
  })
  .sort((a, b) => b.cells[2].value - a.cells[2].value || a.label.localeCompare(b.label));

const negatives = er.matrix.cells.filter((c) => c.deltaEr < 0).length;

const fig1 = heatmap({
  title: 'Evasion rate per transform, with and without the normalization pre-pass',
  subtitle: 'Paired basis, "finding still exists" observation. Lower is better; the third column is the reduction.',
  columns: [
    { label: 'off' },
    { label: 'on' },
    { label: 'Δ', diverging: true },
  ],
  rows: armRows,
  legend: 'Rate 0 — 1, light to dark. Δ is diverging: blue = normalization reduced evasion, red = it lost a detection, neutral = no change.',
  caption: [
    `No cell falls on the red arm: across ${er.matrix.cells.length} transform x rule cells the pre-pass lost ${negatives} detections, which is the same fact the paired test reports as a one-sided result.`,
    '† negative control. Excluded from the headline; present so the harness can be seen to move when it should.',
    'Read Δ next to n: the smallest strata carry only a handful of pairs, where a single flip moves the rate by a third.',
  ],
});

// ---------------------------------------------------------------- figure 2
const bandit = JSON.parse(readFileSync(join(RESULTS, 'transfer-bandit.json'), 'utf8'));
const TOOLS = ['vibeguard-regex', 'vibeguard-shipped', 'bandit-ast'];
const SHORT = { 'vibeguard-regex': 'lexical', 'vibeguard-shipped': 'shipped', 'bandit-ast': 'AST' };

const byTransform = new Map();
for (const c of bandit.matrix.cells) {
  const cur = byTransform.get(c.transformId) ?? { n: 0, hit: Object.fromEntries(TOOLS.map((t) => [t, 0])) };
  cur.n += c.denominator;
  for (const t of TOOLS) cur.hit[t] += (c[t] ?? 0) * c.denominator;
  byTransform.set(c.transformId, cur);
}

const toolRows = [...byTransform.entries()]
  .map(([id, v]) => ({
    label: id,
    n: v.n,
    cells: TOOLS.map((t) => {
      const value = v.n > 0 ? v.hit[t] / v.n : null;
      return { value, text: pct(value) };
    }),
  }))
  .sort((a, b) => (b.cells[0].value ?? -1) - (a.cells[0].value ?? -1) || a.label.localeCompare(b.label));

const fig2 = heatmap({
  title: 'Evasion rate per transform, by detector analysis style',
  subtitle: `Shared subset where both tools flagged the original (${bandit.coverage.matchedPairsFileLevel} pairs, ${(bandit.coverage.matchedFraction * 100).toFixed(0)}% of Python pairs).`,
  columns: TOOLS.map((t) => ({ label: SHORT[t] })),
  rows: toolRows,
  legend: 'Rate 0 — 1, light to dark. Darker means the transform evaded that detector more often.',
  caption: [
    `The two tools score at different granularities, so the comparison is reading-sensitive; the result JSON records this as "${bandit.hypothesis.verdict}" rather than a verdict on the hypothesis.`,
    'Only families with a detector on both sides appear; the mapping and its coverage are recorded alongside the numbers.',
  ],
});

// ---------------------------------------------------------------- emit
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'evasion-by-arm.svg'), fig1);
writeFileSync(join(OUT, 'evasion-by-tool.svg'), fig2);

// The table view. Colour is never the only channel, and a paper needs the
// numbers in a form it can typeset.
const table = [
  '# Figure data',
  '',
  'Generated from the result JSON by `scripts/sec-b1-figures.mjs`. Do not edit:',
  'regenerate instead, so a figure can never disagree with the measurement.',
  '',
  '## Evasion rate per transform, with and without the pre-pass',
  '',
  '| transform | predicted | n | rate off | rate on | reduction |',
  '|---|---|---|---|---|---|',
  ...armRows.map((r) => `| ${r.label}${r.negativeControl ? ' (negative control)' : ''} | ${r.predicted ?? '-'} | ${r.n} | ${pct(r.cells[0].value)} | ${pct(r.cells[1].value)} | ${pct(r.cells[2].value)} |`),
  '',
  '## Evasion rate per transform, by detector analysis style',
  '',
  `| transform | n | ${TOOLS.map((t) => SHORT[t]).join(' | ')} |`,
  `|---|---|${TOOLS.map(() => '---').join('|')}|`,
  ...toolRows.map((r) => `| ${r.label} | ${r.n} | ${r.cells.map((c) => pct(c.value)).join(' | ')} |`),
  '',
].join('\n');
writeFileSync(join(OUT, 'figure-data.md'), table);

console.log(`figures -> ${OUT}`);
console.log(`  evasion-by-arm.svg   ${armRows.length} transforms`);
console.log(`  evasion-by-tool.svg  ${toolRows.length} transforms x ${TOOLS.length} tools`);
console.log(`  figure-data.md       table view`);
console.log(`losing-direction cells: ${negatives} of ${er.matrix.cells.length}`);
