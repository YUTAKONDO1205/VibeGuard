// VG-EMB 18b FIX-EMB — honest firmware-footprint measurement for embedded fixes.
//
// WHAT THIS SALVAGES FROM THE OLD CONSTRUCT, AND WHAT IT DROPS. The old plan was
// "measure the scanner's power/latency". That is a category error: VibeGuard
// runs at build/PR time and never touches the firmware runtime, so there is
// nothing on-device to measure. What DOES make sense — and is what this file
// does — is measuring the FIRMWARE AFTER A FIX is applied: replacing strcpy with
// snprintf grows .text, enabling TLS verification costs a cert store in flash.
// That is a real, on-device consequence of accepting a fix.
//
// THE ONE INVARIANT: never present an unmeasured number as measured.
// `measuredWith` is populated ONLY from captured `--version` output, and every
// delta is `null` unless a real `size` run produced it. A null is rendered as
// "not measured (<reason>)", never as 0.
//
// The arm-none-eabi toolchain is frequently absent (CI, this dev box). That is
// the DEFAULT path, not an error: probe once, and when it is missing every
// footprint is null with reason 'toolchain-absent'. Real numbers arrive
// whenever the toolchain does (e.g. `apt install gcc-arm-none-eabi` on the WSL2
// box) with no code change.

/** Berkeley `size` columns for one object. */
export interface SizeReport {
  text: number;
  data: number;
  bss: number;
}

export interface Footprint {
  /** (text+data) after − before, in bytes. null when not measured. */
  flashDelta: number | null;
  /** (data+bss) after − before, in bytes. null when not measured. */
  ramDelta: number | null;
  /** Verbatim first line of `arm-none-eabi-size --version`, or null. */
  measuredWith: string | null;
  /**
   * Why a delta is null. The four are deliberately distinct because they are
   * four different claims about the world:
   *   - 'toolchain-absent'  : we never ran an instrument.
   *   - 'compile-failed'    : we ran the compiler and it refused this specimen.
   *   - 'not-applicable'    : the pair cannot be a bare-metal translation unit at
   *                           all (an Arduino-API fix needs a board core).
   *   - 'no-fix-produced'   : the fixer returned no edits for this specimen, so
   *                           there is no "after" side to compile. This is a
   *                           statement about VibeGuard, not about the toolchain,
   *                           and collapsing it into 'compile-failed' would blame
   *                           the compiler for our own abstention.
   */
  reason?: 'toolchain-absent' | 'compile-failed' | 'not-applicable' | 'no-fix-produced';
}

/**
 * Parse Berkeley-format `arm-none-eabi-size` output. Returns null if no data row
 * is found — a parse failure must not masquerade as a zero-size object.
 *
 *    text    data     bss     dec     hex filename
 *     916       0       0     916     394 a.o
 */
export function parseSizeOutput(out: string): SizeReport | null {
  const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    // Skip the header row (starts with a non-digit label).
    const cols = line.split(/\s+/);
    if (cols.length < 3) continue;
    const [text, data, bss] = [cols[0], cols[1], cols[2]].map((c) => Number(c));
    if (Number.isInteger(text) && Number.isInteger(data) && Number.isInteger(bss)) {
      return { text: text!, data: data!, bss: bss! };
    }
  }
  return null;
}

/** Flash = text+data, RAM = data+bss. Deltas are after − before. */
export function computeFootprint(
  before: SizeReport,
  after: SizeReport,
  measuredWith: string,
): Footprint {
  return {
    flashDelta: after.text + after.data - (before.text + before.data),
    ramDelta: after.data + after.bss - (before.data + before.bss),
    measuredWith,
  };
}

/** The honest all-null footprint for a given reason. */
export function nullFootprint(reason: NonNullable<Footprint['reason']>): Footprint {
  return { flashDelta: null, ramDelta: null, measuredWith: null, reason };
}

/** Minimal spawn signature — lets tests inject without child_process. */
export type SpawnLike = (
  cmd: string,
  args: string[],
) => { status: number | null; stdout: string; error?: { code?: string } };

/**
 * Probe for the arm toolchain. `measuredWith` is the captured `--version` first
 * line — it is structurally impossible to claim an instrument that was not run.
 */
export function probeArmToolchain(spawn: SpawnLike): { present: boolean; version: string | null } {
  const r = spawn('arm-none-eabi-size', ['--version']);
  if (r.error || r.status !== 0 || !r.stdout) return { present: false, version: null };
  const version = r.stdout.split('\n')[0]?.trim() || null;
  return { present: version != null, version };
}

/**
 * A compile+size step for one source, injected so the orchestration is testable.
 *
 * `extraFlags` exists for specimens that reference a constant from a library
 * header the bare-metal sysroot does not ship (mbedTLS' authmode constants are
 * the live case): the value is supplied with `-D…` instead of being re-`#define`d
 * inside the specimen. Two reasons, both about not lying:
 *   - a `#define MBEDTLS_SSL_VERIFY_NONE 0` line inside the specimen is itself a
 *     match for the rule under test, so the specimen would report two findings
 *     and the fixer would rewrite the definition as well as the call site;
 *   - the flags are applied to BOTH sides of the pair, so they cannot bias a
 *     delta — whatever they cost, they cost identically before and after.
 * They are NOT a licence to stub a function body: a specimen that needs code we
 * invented to link is a specimen we are not measuring, and it must fail to
 * compile (→ null) rather than be propped up.
 */
export type CompileAndSize = (source: string, extraFlags?: readonly string[]) => SizeReport | null;

/**
 * Measure a before/after fix pair. Returns a null footprint (with a reason) when
 * the toolchain is absent or either side fails to compile — never a fabricated
 * number.
 */
export function measureFootprint(
  beforeSource: string,
  afterSource: string,
  deps: { probe: () => { present: boolean; version: string | null }; compileAndSize: CompileAndSize },
): Footprint {
  const { present, version } = deps.probe();
  if (!present || !version) return nullFootprint('toolchain-absent');
  const before = deps.compileAndSize(beforeSource);
  const after = deps.compileAndSize(afterSource);
  if (!before || !after) return nullFootprint('compile-failed');
  return computeFootprint(before, after, version);
}

/**
 * Format ONE delta. This is the single place where null-vs-zero is decided, and
 * it is exported so no renderer has to re-derive the rule:
 *
 *   null  → "not measured (<reason>)"   — no instrument produced this number.
 *   0     → "+0 B"                      — an instrument produced this number and
 *                                         it is zero, which is a real result:
 *                                         flipping `#define DEBUG 1` to 0 in a
 *                                         build where nothing is `#if DEBUG`-
 *                                         guarded genuinely costs nothing.
 *
 * "+0 B" and "not measured" must never be interchangeable in either direction.
 */
export function formatDelta(fp: Footprint, delta: number | null): string {
  if (delta === null) return `not measured (${fp.reason ?? 'unavailable'})`;
  return `${delta >= 0 ? '+' : ''}${delta} B`;
}

/** Render a footprint honestly: a null delta is "not measured", never "0 B". */
export function renderFootprint(fp: Footprint): string {
  const fmt = (d: number | null): string =>
    d === null
      ? formatDelta(fp, d)
      : `${formatDelta(fp, d)}${fp.measuredWith ? ` (${fp.measuredWith})` : ''}`;
  return `flash Δ: ${fmt(fp.flashDelta)}; ram Δ: ${fmt(fp.ramDelta)}`;
}

// ── the table layer ───────────────────────────────────────────────────────────
//
// One pair is measured by `measureFootprint` above. A TABLE of pairs is what the
// paper and docs actually cite, and the table is where the two honesty failures
// live that a single pair cannot express:
//
//   1. PROVENANCE. "strcpy → snprintf costs 24 bytes" and "VibeGuard's fixer
//      costs 24 bytes" are different claims. The first is a hand-typed
//      illustration of a fix shape; the second is a measurement of our own
//      output. `FixPair.source` makes the distinction structural — a row cannot
//      exist without declaring which it is — and the renderer keeps the two in
//      separate tables so no reader merges them by accident.
//   2. ONE INSTRUMENT PER TABLE. `measureAll` probes the toolchain ONCE and
//      reuses that answer for every row, so a table can never carry two
//      different `measuredWith` strings (a toolchain swapped mid-run would
//      otherwise produce rows that are silently not comparable).

/** A before/after specimen pair, with its provenance. */
export interface FixPair {
  /** Rule ID the specimen is built for (e.g. 'VG-EMB-020'). */
  id: string;
  /** One-line description of the transformation, for the table. */
  label: string;
  /**
   * REQUIRED, and required for a reason. 'fixer-output' asserts `after` is
   * literally what `buildFix()` + `applyFixes()` emitted for `before` — the
   * whole point of the exercise, since it makes "we measured the fixer's own
   * patch" verifiable rather than claimed. 'hand-written' means a human typed
   * the after side to illustrate a fix that has NO fixer behind it. Both are
   * legitimate rows; presenting the second as the first is not.
   */
  source: 'fixer-output' | 'hand-written';
  before: string;
  /** The after side, or null when there is nothing to compile. */
  after: string | null;
  /**
   * Required when `after` is null: which of the two "nothing to measure" cases
   * this is. The TS union makes forgetting it a compile error; at runtime a
   * missing value degrades to 'no-fix-produced', the narrower claim (it says
   * only that this table has no after side, and never that an instrument ran).
   */
  whyNoAfter?: 'not-applicable' | 'no-fix-produced';
  /** Extra compiler flags, applied identically to both sides. See CompileAndSize. */
  extraFlags?: readonly string[];
  /** Free-form caveat rendered under the table (not a substitute for a reason). */
  note?: string;
}

export interface FootprintRow {
  pair: FixPair;
  footprint: Footprint;
}

/**
 * Measure a whole table. Probes once (see above), then routes each pair through
 * the same `measureFootprint` used for a single pair — one code path to audit,
 * not two.
 */
export function measureAll(
  pairs: readonly FixPair[],
  deps: {
    probe: () => { present: boolean; version: string | null };
    compileAndSize: CompileAndSize;
  },
): FootprintRow[] {
  const probed = deps.probe();
  const probe = (): { present: boolean; version: string | null } => probed;
  return pairs.map((pair) => {
    if (pair.after === null) {
      return { pair, footprint: nullFootprint(pair.whyNoAfter ?? 'no-fix-produced') };
    }
    const after = pair.after;
    return {
      pair,
      footprint: measureFootprint(pair.before, after, {
        probe,
        compileAndSize: (source) => deps.compileAndSize(source, pair.extraFlags),
      }),
    };
  });
}

/** `|` is the column separator, so a literal one in a label must be escaped. */
function mdCell(s: string): string {
  return s.replace(/\|/g, '\\|');
}

function tableFor(rows: readonly FootprintRow[]): string[] {
  const out = ['| rule | fix | flash Δ | RAM Δ | measured with |', '|---|---|---|---|---|'];
  for (const { pair, footprint: fp } of rows) {
    out.push(
      `| ${mdCell(pair.id)} | ${mdCell(pair.label)} | ${mdCell(formatDelta(fp, fp.flashDelta))} | ` +
        `${mdCell(formatDelta(fp, fp.ramDelta))} | ${mdCell(fp.measuredWith ?? '—')} |`,
    );
  }
  return out;
}

/**
 * Render the table as markdown, fixer output first and hand-written pairs in a
 * separate table under a heading that says so. The two are never interleaved.
 */
export function renderMarkdownTable(rows: readonly FootprintRow[]): string {
  const measured = rows.filter((r) => r.pair.source === 'fixer-output');
  const illustrative = rows.filter((r) => r.pair.source === 'hand-written');
  const out: string[] = [];

  out.push('### Measured on the fixers\' own output');
  out.push('');
  out.push(
    'Each `after` below is the byte-for-byte result of `buildFix()` + `applyFixes()`',
    'run on the `before` specimen — not a hand-written idea of what the fix looks like.',
  );
  out.push('');
  out.push(...(measured.length ? tableFor(measured) : ['(no fixer-output rows)']));

  if (illustrative.length) {
    out.push('');
    out.push('### Illustrative pairs — hand-written, NOT fixer output');
    out.push('');
    out.push(
      'VibeGuard ships no fixer for these rules (the safe replacement needs a buffer',
      'size the source does not contain). The `after` side was typed by a human, so',
      'these numbers describe the SHAPE of the fix, not any patch VibeGuard emits.',
    );
    out.push('');
    out.push(...tableFor(illustrative));
  }

  const notes = rows.filter((r) => r.pair.note);
  if (notes.length) {
    out.push('');
    out.push('Notes:');
    out.push('');
    for (const { pair } of notes) out.push(`- **${pair.id}** — ${pair.note}`);
  }
  return out.join('\n');
}
