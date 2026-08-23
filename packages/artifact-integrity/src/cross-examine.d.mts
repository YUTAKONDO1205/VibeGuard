// Types for `cross-examine.mjs`. See the note in `bundle.d.mts`.

import type { BundleObservation, ProtectionState } from './bundle.d.mts';

export type ProtectionLayer = 'assistant' | 'source' | 'fixer' | 'artifact' | 'sidecar';

export interface ProtectionClaim {
  id: string;
  claimant: string;
  claimantLayer: ProtectionLayer;
  subject: string;
  witness?: string;
  filePath?: string;
  startLine?: number;
  state: ProtectionState;
  crossExaminedAt?: ProtectionLayer;
  note?: string;
}

export declare const CLAIM_BEARING_RULES: Readonly<
  Record<string, { subject: string; witness: (evidence: string) => string | null }>
>;

export declare function identifierWitness(evidence: string): string | null;

export declare function claimsFromFindings(
  findings: { ruleId: string; evidence?: string; filePath?: string; startLine?: number }[],
): ProtectionClaim[];

export declare function claimsFromAssistantProse(
  prose: string,
  options?: { filePath?: string },
): ProtectionClaim[];

export declare function crossExamine(
  claims: ProtectionClaim[],
  observation: BundleObservation,
  illegal: (
    claim: Pick<ProtectionClaim, 'claimantLayer'>,
    observedAt: ProtectionLayer,
    next: ProtectionState,
  ) => string | null,
): ProtectionClaim[];
