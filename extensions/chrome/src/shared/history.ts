// History storage for the VibeGuard side panel.
//
// Per DESIGN §18.3, we deliberately do NOT persist full code. Each entry
// keeps the summary, a small finding digest (no remediation bodies, no
// snippets), and a short text preview of what was scanned. Secrets are
// already masked by the analyzer for category=secrets findings, so what
// we store here is whatever the analyzer chose to surface.
//
// Storage layout:
//   chrome.storage.local["vibeguard.history"] = HistoryEntry[]  (most-recent first)
//
// Entries are capped at HISTORY_MAX. Older entries fall off the end.
//
// All persistence is funnelled through this module so the side panel and
// any future producers (other surfaces, tests) agree on the schema and
// the cap.

import type { Finding, ScanSummary } from '@vibeguard/findings-schema';

export type HistorySource =
  | 'paste'
  | 'page-extract'
  | 'context-menu'
  | 'github-pr-diff';

/**
 * Compact finding row stored in history. Intentionally a subset of Finding:
 * we drop description, remediation, snippet, evidence, references, etc., to
 * keep storage minimal and to avoid persisting full code or model output.
 */
export interface HistoryFinding {
  ruleId: string;
  title: string;
  severity: Finding['severity'];
  filePath?: string;
  startLine?: number;
}

export interface HistoryEntry {
  id: string;
  /** Epoch millis. */
  timestamp: number;
  source: HistorySource;
  /** Best-effort label: page URL, "snippet", or PR URL. */
  origin?: string;
  /** Either a language tag or "multi" for a PR diff spanning several files. */
  language?: string;
  summary: ScanSummary;
  findings: HistoryFinding[];
  /** First ~200 chars of what was scanned, for at-a-glance recall. Newlines kept. */
  codePreview: string;
  /** Total line count of the scanned input (or aggregate for multi-file). */
  totalLines: number;
  /** Number of files when source is github-pr-diff; 1 otherwise. */
  fileCount?: number;
}

export const HISTORY_KEY = 'vibeguard.history';
export const HISTORY_MAX = 50;
export const PREVIEW_CHARS = 200;

/**
 * Minimal subset of chrome.storage.local we depend on. Factored out so
 * tests can supply an in-memory fake without depending on the chrome API.
 */
export interface HistoryStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export function defaultHistoryStorage(): HistoryStorage {
  return {
    get: (key) => chrome.storage.local.get(key),
    set: (items) => chrome.storage.local.set(items),
    remove: (key) => chrome.storage.local.remove(key),
  };
}

function isHistoryEntry(x: unknown): x is HistoryEntry {
  if (!x || typeof x !== 'object') return false;
  const e = x as Partial<HistoryEntry>;
  return (
    typeof e.id === 'string' &&
    typeof e.timestamp === 'number' &&
    typeof e.source === 'string' &&
    Array.isArray(e.findings) &&
    !!e.summary
  );
}

export async function loadHistory(storage: HistoryStorage = defaultHistoryStorage()): Promise<HistoryEntry[]> {
  const rec = await storage.get(HISTORY_KEY);
  const raw = rec[HISTORY_KEY];
  if (!Array.isArray(raw)) return [];
  return raw.filter(isHistoryEntry);
}

export async function appendHistory(
  entry: HistoryEntry,
  storage: HistoryStorage = defaultHistoryStorage(),
): Promise<HistoryEntry[]> {
  const existing = await loadHistory(storage);
  const next = [entry, ...existing].slice(0, HISTORY_MAX);
  await storage.set({ [HISTORY_KEY]: next });
  return next;
}

export async function clearHistory(storage: HistoryStorage = defaultHistoryStorage()): Promise<void> {
  await storage.remove(HISTORY_KEY);
}

/**
 * Build a digest entry from a raw scan result, ready to persist. The caller
 * supplies the input text and metadata; this helper handles preview slicing
 * and finding compaction.
 */
export interface BuildEntryInput {
  source: HistorySource;
  origin?: string;
  language?: string;
  summary: ScanSummary;
  findings: Finding[];
  /**
   * Either the raw input text (single-snippet scans) or a synthesised
   * description (e.g. "3 files (a.ts, b.ts, c.py)" for PR diffs). Sliced
   * to PREVIEW_CHARS.
   */
  codeForPreview: string;
  totalLines: number;
  fileCount?: number;
  /** ID injector for tests. Defaults to a timestamp-based id. */
  newId?: () => string;
  /** Cap how many findings we keep per entry. Defaults to 20. */
  maxFindings?: number;
}

let _counter = 0;
function defaultId(): string {
  _counter += 1;
  return `vg-h-${Date.now().toString(36)}-${_counter.toString(36)}`;
}

export function buildHistoryEntry(input: BuildEntryInput): HistoryEntry {
  const maxFindings = input.maxFindings ?? 20;
  const findings: HistoryFinding[] = input.findings.slice(0, maxFindings).map((f) => ({
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    filePath: f.filePath,
    startLine: f.startLine,
  }));
  const preview = input.codeForPreview.length > PREVIEW_CHARS
    ? `${input.codeForPreview.slice(0, PREVIEW_CHARS)}…`
    : input.codeForPreview;
  return {
    id: (input.newId ?? defaultId)(),
    timestamp: Date.now(),
    source: input.source,
    origin: input.origin,
    language: input.language,
    summary: input.summary,
    findings,
    codePreview: preview,
    totalLines: input.totalLines,
    fileCount: input.fileCount,
  };
}
