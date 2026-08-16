// contrast — recompute every colour pair the site actually renders, and fail the
// build when one of them stops being readable.
//
// WHY THIS EXISTS
//
// The design of this site is written down as a table of HEX values with a
// contrast ratio next to each one. A table like that is true on the day it is
// written and drifts silently afterwards: someone nudges a green half a step to
// make a button look better, the number in the comment beside it stays where it
// was, and the page keeps shipping with a claim nobody rechecked. The failure is
// invisible in review — a diff of `#3E7A33` to `#4A8A3E` looks like nothing.
//
// So the ratios are not maintained by hand. This reads site/src/styles/tokens.css,
// resolves the tokens the way the browser's cascade would, and recomputes the
// pairs. It runs in CI. Changing a HEX and leaving the build green is proof the
// pair is still fine; changing a HEX and breaking the build is the point.
//
// WHY THE PAIR LIST IS WRITTEN OUT BY HAND HERE
//
// It would be possible to check every token against every surface. That produces
// a wall of combinations most of which the site never renders — `--vg-sev-low`
// on `--vg-brand-soft` is not a thing that exists — and a checker that reports
// failures for pairs nobody draws gets its threshold lowered until it is quiet.
// The list below is instead the set of pairs the CSS genuinely creates, each one
// annotated with where. That makes it reviewable: if a component starts drawing
// a pair that is not in this file, the omission is the bug.
//
// WHY THERE ARE MORE THAN TWO ENVIRONMENTS
//
// Bands re-define foreground tokens in their own scope, which is what lets a
// component say `var(--vg-sev-high)` and be correct on white and on near-black.
// The consequence for this checker is that "the value of --vg-sev-high" is not a
// single thing: it depends on which scope the element is in. Each scope that
// re-defines tokens is therefore its own environment here, built by layering the
// scope's declarations over the root's exactly as the cascade does.
//
//   node site/scripts/contrast.mjs
//
// Exit 0 when every pair clears its floor, 1 otherwise with the failures named.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const SITE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOKENS_CSS = join(SITE_ROOT, 'src', 'styles', 'tokens.css');

// ── Reading tokens.css ──────────────────────────────────────────────────────
//
// The blocks are found by sentinel comment rather than by matching selectors.
// Matching `:root` would work today and break the moment the dark block gains a
// second selector or someone reorders the file, and it would break by finding
// nothing — which in a checker means passing. A missing sentinel is a hard error
// below for the same reason: the one outcome this file must never produce is a
// green tick earned by having examined zero pairs.

/** Every scope this checker knows how to read, in the order they appear. */
const SCOPES = ['light', 'code', 'dark', 'fg-dark', 'circle-dark'];

/**
 * Pull the declaration block that follows `/* contrast-scope: <name> *\/`.
 *
 * Brace matching rather than a regex: the dark scope's sentinel sits inside an
 * `@media` block, so "text between the next { and the next }" is not the same
 * thing as "the block that follows".
 */
function readScope(css, name) {
  const marker = `contrast-scope: ${name}`;
  const at = css.indexOf(marker);
  if (at === -1) {
    throw new Error(
      `tokens.css has no '${marker}' sentinel. Either the scope was removed — in ` +
        `which case delete it from SCOPES here — or the comment was lost in an edit, ` +
        `in which case this checker was about to skip a whole environment.`,
    );
  }
  const open = css.indexOf('{', at);
  if (open === -1) throw new Error(`No declaration block follows '${marker}'.`);

  let depth = 0;
  let close = -1;
  for (let i = open; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1;
    else if (css[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close === -1) throw new Error(`Unbalanced braces after '${marker}'.`);

  const body = css.slice(open + 1, close).replace(/\/\*[\s\S]*?\*\//g, '');
  const decls = new Map();
  for (const m of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
    decls.set(m[1], m[2].trim());
  }
  return decls;
}

const css = readFileSync(TOKENS_CSS, 'utf8');
const scopes = new Map(SCOPES.map((name) => [name, readScope(css, name)]));

// The eighteen colour tokens are frozen by the design; the scale tokens are not
// checked here but their absence would mean this file read the wrong block.
const COLOUR_TOKENS = [
  '--vg-surface-base',
  '--vg-surface-tint',
  '--vg-surface-code',
  '--vg-surface-news',
  '--vg-ink',
  '--vg-ink-muted',
  '--vg-ink-on-code',
  '--vg-brand',
  '--vg-brand-strong',
  '--vg-brand-soft',
  '--vg-rule',
  '--vg-focus',
  '--vg-sev-critical',
  '--vg-sev-high',
  '--vg-sev-medium',
  '--vg-sev-low',
  '--vg-status-available',
  '--vg-status-research',
];

for (const token of COLOUR_TOKENS) {
  if (!scopes.get('light').has(token)) {
    throw new Error(`${token} is missing from the light scope of tokens.css.`);
  }
}

// ── Resolving a token in an environment ─────────────────────────────────────

/**
 * Layer scopes the way the cascade does: later layers win, and a `var(--other)`
 * resolves against the merged result rather than against the layer it was
 * written in. That second part is what makes `--vg-ink: var(--vg-ink-on-code)`
 * inside the code band mean "whatever ink-on-code is in the active scheme".
 */
function resolve(env, token, seen = new Set()) {
  if (seen.has(token)) throw new Error(`${token} resolves to itself in ${env.name}.`);
  seen.add(token);

  let value;
  for (const layer of env.layers) {
    const decls = scopes.get(layer);
    if (decls.has(token)) value = decls.get(token);
  }
  if (value === undefined) throw new Error(`${token} is undefined in ${env.name}.`);

  const ref = value.match(/^var\(\s*(--[\w-]+)\s*\)$/);
  if (ref) return resolve(env, ref[1], seen);
  if (!/^#[0-9a-fA-F]{6}$/.test(value)) {
    throw new Error(`${token} in ${env.name} is '${value}', which is not a 6-digit hex.`);
  }
  return value.toUpperCase();
}

// ── WCAG 2.x relative luminance ─────────────────────────────────────────────

function channel(eightBit) {
  const c = eightBit / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function luminance(hex) {
  const r = channel(parseInt(hex.slice(1, 3), 16));
  const g = channel(parseInt(hex.slice(3, 5), 16));
  const b = channel(parseInt(hex.slice(5, 7), 16));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a, b) {
  const la = luminance(a);
  const lb = luminance(b);
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

// ── Floors ──────────────────────────────────────────────────────────────────
//
// `text` is body copy and anything at a body size. `large` is the hero finding
// and the band headings, which are well past 24px / 19px bold. `nontext` covers
// what WCAG 1.4.11 covers — a focus ring, the outline of a badge, a pictogram
// that a sighted reader is expected to make out — plus the one glyph that is
// decoration but still visibly text-shaped.
//
// `info` has no floor and is printed anyway. Those rows exist so that the two
// numbers this design depends on being LOW stay visible: the rules are meant to
// be faint, and adjacent bands are meant to be nearly the same colour. Both
// facts are the reason bands.css draws a 1px line at every boundary, and a
// checker that hid them would let someone "fix" the low ratio by darkening the
// rule, which is a different design.
const FLOOR = { text: 4.5, large: 3.0, nontext: 3.0, info: null };

// ── Environments ────────────────────────────────────────────────────────────

const ENVS = {
  light: { name: 'light', layers: ['light'] },
  dark: { name: 'dark', layers: ['light', 'dark'] },
  lightCode: { name: 'light · code band', layers: ['light', 'code'] },
  darkCode: { name: 'dark · code band', layers: ['light', 'dark', 'code'] },
  // The circle and the link/badge scopes have no light-scheme override; the
  // light entry is the plain root, which is exactly what the browser resolves.
  lightCircle: { name: 'light · icon circle', layers: ['light'] },
  darkCircle: { name: 'dark · icon circle', layers: ['light', 'dark', 'circle-dark'] },
  lightFg: { name: 'light · link / NEW', layers: ['light'] },
  darkFg: { name: 'dark · link / NEW', layers: ['light', 'dark', 'fg-dark'] },
};

// ── The pairs the site draws ────────────────────────────────────────────────
//
// [ foreground, background, kind, where it is rendered ]

const ROOT_PAIRS = [
  ['--vg-ink', '--vg-surface-base', 'text', 'body copy on the base bands'],
  ['--vg-ink', '--vg-surface-tint', 'text', 'labels under the category circles'],
  ['--vg-ink', '--vg-surface-news', 'text', 'news headlines'],
  ['--vg-ink-muted', '--vg-surface-base', 'text', 'captions, screenshot captions'],
  ['--vg-ink-muted', '--vg-surface-tint', 'text', 'category blurbs and rule counts'],
  ['--vg-ink-muted', '--vg-surface-news', 'text', 'news dates'],
  ['--vg-ink', '--vg-brand-soft', 'text', 'text inside a soft-filled badge'],
  ['--vg-ink-muted', '--vg-brand-soft', 'text', 'secondary text inside a soft badge'],

  ['--vg-brand', '--vg-surface-base', 'text', 'the // heading mark on base bands'],
  ['--vg-brand', '--vg-surface-tint', 'text', 'the // heading mark on the tint band'],
  [
    '--vg-brand',
    '--vg-surface-news',
    'nontext',
    'the // heading mark and the NEW outline on the news band — the mark is aria-hidden ornament and the outline is a shape, so 3.0 applies; the badge word NEW carries the meaning',
  ],

  ['--vg-ink-on-code', '--vg-brand-strong', 'text', 'the CTA label on its fill'],
  ['--vg-brand-strong', '--vg-surface-base', 'nontext', 'the CTA fill against the band behind it'],

  ['--vg-focus', '--vg-surface-base', 'nontext', 'focus ring on base bands'],
  ['--vg-focus', '--vg-surface-tint', 'nontext', 'focus ring on the tint band'],
  ['--vg-focus', '--vg-surface-news', 'nontext', 'focus ring on the news band'],

  ['--vg-sev-critical', '--vg-surface-base', 'text', 'the word CRITICAL on a base band'],
  ['--vg-sev-high', '--vg-surface-base', 'text', 'the word HIGH on a base band'],
  ['--vg-sev-medium', '--vg-surface-base', 'text', 'the word MEDIUM on a base band'],
  ['--vg-sev-low', '--vg-surface-base', 'text', 'the word LOW on a base band'],
  ['--vg-sev-critical', '--vg-surface-tint', 'text', 'the word CRITICAL on the tint band'],
  ['--vg-sev-high', '--vg-surface-tint', 'text', 'the word HIGH on the tint band'],
  ['--vg-sev-medium', '--vg-surface-tint', 'text', 'the word MEDIUM on the tint band'],
  ['--vg-sev-low', '--vg-surface-tint', 'text', 'the word LOW on the tint band'],

  ['--vg-status-available', '--vg-brand-soft', 'text', 'the word Available on its pill'],
  ['--vg-status-research', '--vg-surface-base', 'text', 'the word Research on a base band'],
  ['--vg-status-research', '--vg-surface-tint', 'text', 'the word Research on the tint band'],
  ['--vg-status-research', '--vg-surface-news', 'text', 'the word Research in the research banner'],

  ['--vg-rule', '--vg-surface-base', 'info', 'band boundary and card frames — decorative by design'],
  ['--vg-rule', '--vg-surface-news', 'info', 'the dashed separator in the news list'],
  ['--vg-surface-tint', '--vg-surface-base', 'info', 'adjacent bands — why the 1px rule is mandatory'],
  ['--vg-surface-news', '--vg-surface-base', 'info', 'adjacent bands — why the 1px rule is mandatory'],
];

const CODE_PAIRS = [
  ['--vg-ink', '--vg-surface-code', 'text', 'code and finding text on the code band'],
  ['--vg-ink-muted', '--vg-surface-code', 'text', 'line numbers, file path, rule id, confidence'],
  ['--vg-brand', '--vg-surface-code', 'text', 'the + of an added line and its left edge'],
  ['--vg-brand-strong', '--vg-surface-code', 'text', 'the /rules link in the note under the triptych'],
  ['--vg-focus', '--vg-surface-code', 'nontext', 'focus ring on the code band'],
  ['--vg-sev-critical', '--vg-surface-code', 'text', 'CRITICAL and its wavy underline'],
  ['--vg-sev-high', '--vg-surface-code', 'text', 'HIGH and its wavy underline'],
  ['--vg-sev-medium', '--vg-surface-code', 'text', 'MEDIUM and its wavy underline'],
  ['--vg-sev-low', '--vg-surface-code', 'text', 'LOW and its wavy underline'],
  ['--vg-ink', '--vg-surface-code', 'large', 'the hero finding at --vg-fs-900'],
  ['--vg-rule', '--vg-surface-code', 'info', 'the frame around a code block — decorative'],
];

const CIRCLE_PAIRS = [
  [
    '--vg-ink-on-code',
    '--vg-brand',
    'nontext',
    'the pictogram stroked on a category circle; the label under the circle names it',
  ],
];

const FG_PAIRS = [
  ['--vg-brand-strong', '--vg-surface-base', 'text', 'links on the base bands'],
  ['--vg-brand-strong', '--vg-surface-tint', 'text', 'links on the tint band'],
  ['--vg-brand-strong', '--vg-surface-news', 'text', 'news links and the word NEW'],
];

const GROUPS = [
  { envs: [ENVS.light, ENVS.dark], pairs: ROOT_PAIRS },
  { envs: [ENVS.lightCode, ENVS.darkCode], pairs: CODE_PAIRS },
  { envs: [ENVS.lightCircle, ENVS.darkCircle], pairs: CIRCLE_PAIRS },
  { envs: [ENVS.lightFg, ENVS.darkFg], pairs: FG_PAIRS },
];

// ── Run ─────────────────────────────────────────────────────────────────────

const rows = [];
const failures = [];

for (const group of GROUPS) {
  for (const env of group.envs) {
    for (const [fgToken, bgToken, kind, where] of group.pairs) {
      const fg = resolve(env, fgToken);
      const bg = resolve(env, bgToken);
      const value = ratio(fg, bg);
      const floor = FLOOR[kind];
      const ok = floor === null || value + 1e-9 >= floor;
      rows.push({ env: env.name, fgToken, fg, bgToken, bg, kind, value, floor, ok });
      if (!ok) failures.push({ env: env.name, fgToken, bgToken, value, floor, where });
    }
  }
}

const COLUMNS = [
  { head: 'scope', get: (r) => r.env },
  { head: 'foreground', get: (r) => `${r.fgToken} ${r.fg}` },
  { head: 'background', get: (r) => `${r.bgToken} ${r.bg}` },
  { head: 'use', get: (r) => r.kind },
  { head: 'ratio', get: (r) => r.value.toFixed(2), right: true },
  { head: 'min', get: (r) => (r.floor === null ? '—' : r.floor.toFixed(1)), right: true },
  { head: '', get: (r) => (r.floor === null ? 'note' : r.ok ? 'ok' : 'FAIL') },
];

const widths = COLUMNS.map((c) =>
  Math.max(c.head.length, ...rows.map((r) => String(c.get(r)).length)),
);

function line(cells) {
  return cells
    .map((cell, i) => (COLUMNS[i].right ? String(cell).padStart(widths[i]) : String(cell).padEnd(widths[i])))
    .join('  ')
    .trimEnd();
}

console.log(line(COLUMNS.map((c) => c.head)));
console.log(widths.map((w) => '-'.repeat(w)).join('  '));

let previousEnv = null;
for (const r of rows) {
  if (previousEnv !== null && r.env !== previousEnv) console.log('');
  previousEnv = r.env;
  console.log(line(COLUMNS.map((c) => c.get(r))));
}

console.log('');
if (failures.length > 0) {
  console.error(`${failures.length} pair(s) below the floor:`);
  for (const f of failures) {
    console.error(
      `  ${f.env}: ${f.fgToken} on ${f.bgToken} is ${f.value.toFixed(2)}, needs ${f.floor.toFixed(1)}`,
    );
    console.error(`    rendered as: ${f.where}`);
  }
  process.exit(1);
}

const checked = rows.filter((r) => r.floor !== null).length;
console.log(`${checked} pair(s) checked against a floor, ${rows.length - checked} noted. All clear.`);
