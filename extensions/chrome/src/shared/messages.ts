// Typed message contracts between the side panel and the background service
// worker.  Keep these flat (no functions) so they survive structuredClone.

import type { ParsedDiffFile } from './diff-reconstruct.js';

export type ScanSource = 'paste' | 'page-extract' | 'context-menu' | 'github-pr-diff';

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

/**
 * Request the background worker to walk the active tab for a GitHub PR diff
 * (Files-changed view) and return one ParsedDiffFile per touched file.
 */
export interface RequestGithubDiffMessage {
  type: 'vibeguard.extractGithubDiff';
}

export interface GithubDiffResultMessage {
  type: 'vibeguard.githubDiffResult';
  /** PR URL the diff came from, when available. */
  origin: string;
  files: ParsedDiffFile[];
  /**
   * Files this PR changes that the page did NOT render, so nothing could be
   * read from them.
   *
   * GitHub collapses the diffs of a large PR behind "Load diff" and never puts
   * their rows in the DOM. Measured on rust-lang/rust#160102: 284 changed
   * files, 121 with diff tables, 163 collapsed — and scrolling to the bottom
   * does not change those numbers, so this is not lazy loading a user can wait
   * out. Without this field the side panel reported "121 file(s)" and a clean
   * verdict for a PR it had seen 43% of.
   *
   * Empty when the page rendered everything.
   */
  skippedFiles: string[];
  /** Soft error: nothing to scan, wrong page, etc. */
  error?: string;
}

export type VibeGuardMessage =
  | PushCodeMessage
  | RequestExtractMessage
  | ExtractResultMessage
  | RequestGithubDiffMessage
  | GithubDiffResultMessage;
