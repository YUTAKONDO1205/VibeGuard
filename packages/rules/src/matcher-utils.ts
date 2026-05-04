import type { RuleMatch } from './rule-types.js';

export interface Position {
  line: number;
  column: number;
}

export function indexToPosition(content: string, index: number): Position {
  let line = 1;
  let column = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

export function getLineText(lines: string[], lineNumber: number): string {
  return lines[lineNumber - 1] ?? '';
}

/**
 * Run a global regex against the source and convert each match into a RuleMatch.
 * Pattern MUST have the global flag.
 */
export function runRegex(
  content: string,
  pattern: RegExp,
  options?: {
    /** When true, skip matches whose line is in a comment-only context (// or # at line start ignoring whitespace). */
    skipCommentLines?: boolean;
    /** Maximum matches to return. */
    limit?: number;
  },
): RuleMatch[] {
  if (!pattern.global) {
    throw new Error(`pattern must be global: ${pattern}`);
  }
  const matches: RuleMatch[] = [];
  const limit = options?.limit ?? 1000;
  let m: RegExpExecArray | null;
  pattern.lastIndex = 0;
  while ((m = pattern.exec(content)) !== null) {
    if (matches.length >= limit) break;
    const start = indexToPosition(content, m.index);
    const end = indexToPosition(content, m.index + m[0].length);
    if (options?.skipCommentLines) {
      const lineText = content.split('\n')[start.line - 1] ?? '';
      const trimmed = lineText.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('#')) {
        if (m[0].length === 0) pattern.lastIndex += 1;
        continue;
      }
    }
    matches.push({
      startLine: start.line,
      endLine: end.line,
      startColumn: start.column,
      endColumn: end.column,
      evidence: m[0],
      variables: m.groups ? { ...m.groups } : undefined,
    });
    if (m[0].length === 0) pattern.lastIndex += 1;
  }
  return matches;
}

export function languageMatches(ruleLanguages: string[], inputLanguage?: string): boolean {
  if (ruleLanguages.includes('*')) return true;
  if (!inputLanguage) return false;
  return ruleLanguages.includes(inputLanguage);
}
