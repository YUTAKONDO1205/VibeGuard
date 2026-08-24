// Types for `bundle.mjs`. Hand-written because this package is plain ESM with
// no build step, and the CLI consumes it under `checkJs: false`.

export type ProtectionState =
  | 'PRESENT'
  | 'ABSENT'
  | 'LOST'
  | 'REINTRODUCED'
  | 'NOT_APPLICABLE'
  | 'NOT_OBSERVED';

/** A run of generated text one source is responsible for. */
export interface SourceRegion {
  start: number;
  end: number;
  source: number;
}

/** One shipped file, its source map's original text, and where each byte came from. */
export interface ArtefactRecord {
  artefact: string;
  bytes: number;
  /** Newline-normalised artefact text, or null when it could not be read. */
  code: string | null;
  /** Newline-normalised join of the map's sourcesContent, or null. */
  sidecar: string | null;
  /**
   * Newline-normalised sourcesContent, INDEX-ALIGNED with `sources` so a
   * mapping segment's source index selects the right entry; null where the map
   * omitted the text.
   */
  contents?: (string | null)[];
  /** Decoded generated-text regions, or null when the map could not be decoded. */
  regions?: SourceRegion[] | null;
  /** Spans too wide to attribute anything, kept only to explain a refusal. */
  coarse?: { start: number; end: number }[];
  /** Why `regions` is null. Absent when it is not. */
  regionsWhy?: string;
  sources?: string[];
  sourcesContentEntries?: number;
  /**
   * False whenever anything stopped this record from being reasoned about.
   * NOT a control that held — see the note in `bundle.mjs`. An undecodable
   * source map leaves this true and `regions` null: the sidecar half of the
   * observation still works, only attribution is lost.
   */
  measured: boolean;
  why?: string;
}

export interface BundleObservation {
  dir: string;
  records: ArtefactRecord[];
  skipped: { path: string; reason: string }[];
  readable: number;
  /** How many of `records` can be reasoned about at all. */
  measured: number;
}

export declare const MAX_ARTEFACT_BYTES: number;
export declare const STATE: Record<ProtectionState, ProtectionState>;

export declare function normaliseText(s: string): string;

export declare function collectArtefacts(dir: string): Promise<{
  artefacts: { path: string; relPath: string; bytes: number }[];
  skipped: { path: string; reason: string }[];
}>;

export declare function sourceMappingUrl(code: string): string | null;

export declare function readSourceMap(
  artefactPath: string,
  code: string,
): Promise<{ map: unknown; origin?: string; why?: string }>;

export declare function observeArtefact(
  path: string,
  relPath: string,
  bytes: number,
): Promise<ArtefactRecord>;

export declare function observeBundleDir(dir: string): Promise<BundleObservation>;
