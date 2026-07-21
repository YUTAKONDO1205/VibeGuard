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
  reason?: 'toolchain-absent' | 'compile-failed' | 'not-applicable';
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

/** A compile+size step for one source, injected so the orchestration is testable. */
export type CompileAndSize = (source: string) => SizeReport | null;

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

/** Render a footprint honestly: a null delta is "not measured", never "0 B". */
export function renderFootprint(fp: Footprint): string {
  const fmt = (d: number | null): string => {
    if (d === null) return `not measured (${fp.reason ?? 'unavailable'})`;
    const sign = d >= 0 ? '+' : '';
    return `${sign}${d} B${fp.measuredWith ? ` (${fp.measuredWith})` : ''}`;
  };
  return `flash Δ: ${fmt(fp.flashDelta)}; ram Δ: ${fmt(fp.ramDelta)}`;
}
