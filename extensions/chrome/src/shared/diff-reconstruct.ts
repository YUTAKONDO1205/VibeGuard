// Pure helpers for GitHub PR diff scanning.
//
// The browser-side extractor reads each file block on a GitHub PR diff view
// and returns the per-line slices it can see: every added line and every
// surrounding context line, each tagged with the *new-file* line number.
// This module turns that flat list into something the analyzer can ingest.
//
// Two design choices worth flagging:
//
//  1. We reconstruct a pseudo file (blank lines outside the diff window) so
//     finding line numbers come back as the real new-file line numbers the
//     user sees on GitHub. The trade-off is that rules that rely on context
//     far from the diff window will under-fire — that is acceptable here,
//     since the user only wants verdicts on the diff itself.
//
//  2. Findings are filtered to those that overlap an added line, the same
//     way the CLI's `scanDiff` filters its full-file scan. Context lines are
//     fed to the analyzer only to give regex rules enough surrounding text
//     to fire correctly; we discard findings that land purely on context.
//
// The DOM extraction itself lives in background.ts because it must run via
// chrome.scripting.executeScript in the page world. Keeping the post-
// processing here lets us unit-test it without a browser.
//
// Both functions are exported as plain helpers so they can be imported by
// the side panel and by vitest tests without pulling in any browser API.

export interface DiffLine {
  /** 1-based line number in the new (post-image) file. */
  ln: number;
  text: string;
  added: boolean;
}

export interface ParsedDiffFile {
  /** Repo-relative path, e.g. `src/foo.ts`. */
  filePath: string;
  /** Language hint pulled from the file extension; analyzer may override. */
  language?: string;
  lines: DiffLine[];
}

/**
 * Build a string where each line N contains the text we saw for that new-file
 * line number, or an empty string if that line wasn't present in the diff.
 *
 * Example: lines = [{ln:3,text:'a'},{ln:5,text:'b'}] →
 *   "" + "\n" + "" + "\n" + "a" + "\n" + "" + "\n" + "b"
 *
 * That keeps `f.startLine` from the analyzer aligned with the line numbers
 * the user reads on GitHub.
 */
export function reconstructPseudoContent(file: ParsedDiffFile): string {
  if (file.lines.length === 0) return '';
  // Sort defensively — extractor may emit hunks out of order in odd DOMs.
  const sorted = [...file.lines].sort((a, b) => a.ln - b.ln);
  const max = sorted[sorted.length - 1]!.ln;
  const buf = new Array<string>(max).fill('');
  for (const line of sorted) {
    if (line.ln >= 1 && line.ln <= max) {
      buf[line.ln - 1] = line.text;
    }
  }
  return buf.join('\n');
}

/** Set of 1-based added line numbers in the new file. */
export function addedLineSet(file: ParsedDiffFile): Set<number> {
  const out = new Set<number>();
  for (const line of file.lines) {
    if (line.added) out.add(line.ln);
  }
  return out;
}

/**
 * Map a file extension to the language tag the analyzer expects. Mirrors a
 * subset of detectLanguageFromPath; we only need this client-side because
 * the analyzer will re-detect from the filePath anyway. We supply a hint
 * for the language picker on the panel.
 */
const EXT_TO_LANG: Record<string, string> = {
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  py: 'python',
  go: 'go',
  java: 'java',
  rb: 'ruby',
  php: 'php',
  cs: 'csharp',
};

export function languageFromPath(filePath: string): string | undefined {
  const dot = filePath.lastIndexOf('.');
  if (dot < 0) return undefined;
  const ext = filePath.slice(dot + 1).toLowerCase();
  return EXT_TO_LANG[ext];
}
