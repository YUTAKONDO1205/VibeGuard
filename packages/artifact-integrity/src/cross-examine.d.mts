// Types for `cross-examine.mjs`. See the note in `bundle.d.mts`.

import type { BundleObservation, ProtectionState } from './bundle.d.mts';

export type ProtectionLayer = 'assistant' | 'source' | 'fixer' | 'artifact' | 'sidecar';

export interface ProtectionClaim {
  id: string;
  claimant: string;
  claimantLayer: ProtectionLayer;
  subject: string;
  witness?: string;
  /** Source text used to decide which artefact this claim is about. */
  sourceProbe?: string;
  history?: { checkpoint: string; state: ProtectionState; where?: string }[];
  filePath?: string;
  startLine?: number;
  state: ProtectionState;
  crossExaminedAt?: ProtectionLayer;
  note?: string;
}

// Claim construction lives in `@vibeguard/findings-schema`; this module only
// adjudicates. See the note at the top of cross-examine.mjs.

export declare function crossExamine(
  claims: ProtectionClaim[],
  observation: BundleObservation,
  illegal: (
    claim: Pick<ProtectionClaim, 'claimantLayer'>,
    observedAt: ProtectionLayer,
    next: ProtectionState,
  ) => string | null,
): ProtectionClaim[];
