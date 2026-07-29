/**
 * Scanning extracted page blocks, as a unit that does not need a DOM.
 *
 * The side panel used to concatenate every `<pre><code>` block on the page into
 * one snippet and scan it once, under one language. That loses findings on any
 * page whose blocks are not all the same language — an AI chat transcript, a
 * tutorial, API docs — and it loses them SILENTLY, because the panel then
 * renders a clean verdict for the page.
 *
 * Measured against the shipped browser core with a Python block calling
 * `subprocess.call(..., shell=True)` and a JavaScript block assigning to
 * `innerHTML`:
 *
 *   joined, scanned as python      -> 1 finding   (the JS sink is lost)
 *   joined, scanned as javascript  -> 1 finding   (the Python sink is lost)
 *   per block, per language        -> 2 findings
 *
 * Whichever language is picked, joining loses the other one's sinks. The
 * separator made it worse: `// --- block N ---` is a JavaScript comment being
 * injected into text that may be Python, where `//` is floor division.
 */
import type { Finding, ScanDegradation, ScanResponse } from '@vibeguard/findings-schema';

export interface ExtractedCodeBlock {
  text: string;
  /** Language tag from the page's `class="language-…"`, when it had one. */
  language?: string;
}

export interface BlockScanResult {
  /** Display label, e.g. `block 2 · python`. */
  label: string;
  language: string;
  lineCount: number;
  findings: Finding[];
  degradations?: ScanDegradation[];
  /**
   * Set when this block produced no findings for a reason other than being
   * clean. An empty finding list means "clean" ONLY when this is absent.
   */
  unscanned?: string;
}

export interface ScanBlocksDeps {
  scan: (req: {
    targetType: 'snippet';
    mode: 'standard';
    content: string;
    language: string;
    filePath: string;
  }) => ScanResponse;
  detectLanguageFromContent: (content: string) => string | undefined;
  /** The panel's language picker — a statement about the PAGE, not a block. */
  fallbackLanguage?: string;
}

/**
 * Language for one block: its own tag first, then content sniffing, then the
 * page-level fallback. The fallback is last precisely because it is the value
 * that used to be applied to everything.
 */
export function languageForBlock(block: ExtractedCodeBlock, deps: ScanBlocksDeps): string {
  return (
    block.language ||
    deps.detectLanguageFromContent(block.text) ||
    deps.fallbackLanguage ||
    'javascript'
  );
}

export function scanBlocks(
  blocks: readonly ExtractedCodeBlock[],
  deps: ScanBlocksDeps,
): BlockScanResult[] {
  return blocks.map((block, i) => {
    const lineCount = block.text.split('\n').length;
    const base = `block ${i + 1}`;
    if (!block.text.trim()) {
      return { label: base, language: 'text', lineCount, findings: [] };
    }
    const language = languageForBlock(block, deps);
    try {
      const result = deps.scan({
        targetType: 'snippet',
        mode: 'standard',
        content: block.text,
        language,
        filePath: base,
      });
      return {
        label: `${base} · ${language}`,
        language,
        lineCount,
        findings: result.findings,
        ...(result.degradations?.length ? { degradations: result.degradations } : {}),
        // A rule that threw contributed no findings. Saying nothing about it
        // renders the block as clean, which is the one thing it is not known
        // to be.
        ...(result.ruleErrors?.length
          ? { unscanned: `${result.ruleErrors.length} rule(s) errored — findings may be missing` }
          : {}),
      };
    } catch (err) {
      // One bad block must not take the page down, and must not be reported as
      // clean either.
      return {
        label: base,
        language,
        lineCount,
        findings: [],
        unscanned: `scan failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  });
}
