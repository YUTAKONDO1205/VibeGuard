// Types for `bundle.mjs`. Hand-written because this package is plain ESM with
// no build step, and the CLI consumes it under `checkJs: false`.

export type ProtectionState =
  | 'PRESENT'
  | 'ABSENT'
  | 'LOST'
  | 'REINTRODUCED'
  | 'NOT_APPLICABLE'
  | 'NOT_OBSERVED';

/** One shipped file, its source map's original text, and whether it can be trusted. */
export interface ArtefactRecord {
  artefact: string;
  bytes: number;
  /** Newline-normalised artefact text, or null when it could not be read. */
  code: string | null;
  /** Newline-normalised join of the map's sourcesContent, or null. */
  sidecar: string | null;
  sources?: string[];
  sourcesContentEntries?: number;
  /** False whenever anything stopped this record from being reasoned about. */
  controlHeld: boolean;
  why?: string;
}

export interface BundleObservation {
  dir: string;
  records: ArtefactRecord[];
  skipped: { path: string; reason: string }[];
  readable: number;
  controlHeld: number;
}

export declare const MAX_ARTEFACT_BYTES: number;
export declare const STATE: Record<ProtectionState, ProtectionState>;
export declare const CANARY: string;

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
