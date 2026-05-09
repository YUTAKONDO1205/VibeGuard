// Typed message contracts between the side panel and the background service
// worker.  Keep these flat (no functions) so they survive structuredClone.

export type ScanSource = 'paste' | 'page-extract' | 'context-menu';

export interface PushCodeMessage {
  type: 'vibeguard.pushCode';
  source: ScanSource;
  /** The text to scan. */
  code: string;
  /** Best-effort source label, shown in the side panel header. */
  origin?: string;
}

export interface RequestExtractMessage {
  type: 'vibeguard.extractFromActiveTab';
}

export interface ExtractedBlock {
  /** Best-effort language tag pulled from class names like `language-ts`. */
  language?: string;
  text: string;
}

export interface ExtractResultMessage {
  type: 'vibeguard.extractResult';
  origin: string;
  blocks: ExtractedBlock[];
  error?: string;
}

export type VibeGuardMessage =
  | PushCodeMessage
  | RequestExtractMessage
  | ExtractResultMessage;
