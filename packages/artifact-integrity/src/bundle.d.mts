// Types for `bundle.mjs`. Hand-written because this package is plain ESM with
// no build step, and the CLI consumes it under `checkJs: false`; without these
// the dynamic import in `apps/cli/src/index.ts` is `any` and TypeScript rejects
// it under `noImplicitAny`.

export type ProtectionState =
  | 'PRESENT'
  | 'ABSENT'
  | 'LOST'
  | 'REINTRODUCED'
  | 'NOT_APPLICABLE'
  | 'NOT_OBSERVED';

export interface WitnessResult {
  witness: string;
  state: ProtectionState;
  inCode: boolean | null;
  inSidecar: boolean | null;
}

export interface ArtefactRecord {
  artefact: string;
  bytes: number;
  state: ProtectionState;
  why?: string;
  sourcesContentEntries?: number;
  witnesses: WitnessResult[];
  controlHeld: boolean;
}

export interface BundleObservation {
  dir: string;
  records: ArtefactRecord[];
  skipped: { path: string; reason: string }[];
}

export declare const MAX_ARTEFACT_BYTES: number;
export declare const STATE: Record<ProtectionState, ProtectionState>;

export declare function collectArtefacts(dir: string): Promise<{
  artefacts: { path: string; relPath: string; bytes: number }[];
  skipped: { path: string; reason: string }[];
}>;

export declare function sourceMappingUrl(code: string): string | null;

export declare function readSourceMap(
  artefactPath: string,
  code: string,
): Promise<{ map: unknown; origin?: string; why?: string }>;

export declare function republishedWitnesses(
  code: string,
  map: unknown,
  witnesses: string[],
  control: string | null,
): { controlHeld: boolean; sourcesContentEntries: number; results: WitnessResult[] };

export declare function observeBundleDir(
  dir: string,
  options?: { witnesses?: string[]; control?: string | null },
): Promise<BundleObservation>;

export declare function worstState(states: ProtectionState[]): ProtectionState;
