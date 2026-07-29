// VibeGuard side panel UI.
//
// Pulls findings out of @vibeguard/analyzer-core (browser subpath, no fs)
// and renders them.  Receives async pushes from:
//   - context-menu "Scan with VibeGuard"  (background → runtime.sendMessage)
//   - "Extract from page" button          (panel → background → executeScript)
//   - "Scan PR diff" button               (panel → background → GitHub diff walk)
//
// Every completed scan appends a digest (summary + finding metadata, NO full
// code) to chrome.storage.local["vibeguard.history"]. The bottom "History"
// section renders the most-recent 50 entries.

import { scan, detectLanguageFromContent } from '@vibeguard/analyzer-core/browser';
import {
  summarize,
  type Finding,
  type RuleError,
  type ScanDegradation,
  type ScanSummary,
} from '@vibeguard/findings-schema';
import {
  scanBlocks,
  type ExtractedCodeBlock,
} from '../shared/block-scan.js';
import {
  addedLineSet,
  languageFromPath,
  reconstructPseudoContent,
  type ParsedDiffFile,
} from '../shared/diff-reconstruct.js';
import {
  appendHistory,
  buildHistoryEntry,
  clearHistory,
  loadHistory,
  type HistoryEntry,
  type HistorySource,
} from '../shared/history.js';
import type {
  ExtractResultMessage,
  GithubDiffResultMessage,
  PushCodeMessage,
  RequestExtractMessage,
  RequestGithubDiffMessage,
  VibeGuardMessage,
} from '../shared/messages.js';

const $ = <T extends Element>(sel: string): T => {
  const el = document.querySelector<T>(sel);
  if (!el) throw new Error(`missing element: ${sel}`);
  return el;
};

const codeArea = $<HTMLTextAreaElement>('#code');
const langSelect = $<HTMLSelectElement>('#lang');
const scanBtn = $<HTMLButtonElement>('#scan');
const clearBtn = $<HTMLButtonElement>('#clear');
const extractBtn = $<HTMLButtonElement>('#extract');
const scanPrBtn = $<HTMLButtonElement>('#scan-pr');
const statusEl = $<HTMLSpanElement>('#status');
const originEl = $<HTMLParagraphElement>('#origin');
const findingsEl = $<HTMLElement>('#findings');
const historyListEl = $<HTMLElement>('#history-list');
const historyCountEl = $<HTMLElement>('#history-count');
const historyClearBtn = $<HTMLButtonElement>('#history-clear');

function setStatus(msg: string): void {
  statusEl.textContent = msg;
}

function setOrigin(origin: string): void {
  originEl.textContent = origin;
}

// --- shared finding card --------------------------------------------------

function buildSummaryBar(counts: ScanSummary): HTMLElement {
  const summary = document.createElement('div');
  summary.className = 'vg-summary';
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    if (counts[sev]) {
      const tag = document.createElement('span');
      tag.textContent = `${sev}: ${counts[sev]}`;
      summary.appendChild(tag);
    }
  }
  return summary;
}

function buildFindingCard(f: Finding, opts: { showFilePath?: boolean } = {}): HTMLElement {
  const card = document.createElement('article');
  card.className = 'vg-finding';
  card.dataset.severity = f.severity;

  const header = document.createElement('header');
  const title = document.createElement('span');
  title.className = 'vg-title';
  title.textContent = f.title;
  const sev = document.createElement('span');
  sev.className = 'vg-sev';
  sev.textContent = f.severity;
  const rule = document.createElement('span');
  rule.className = 'vg-rule';
  rule.textContent = f.ruleId;
  const loc = document.createElement('span');
  loc.className = 'vg-loc';
  const locText: string[] = [];
  if (opts.showFilePath && f.filePath) locText.push(f.filePath);
  if (f.startLine) locText.push(`L${f.startLine}`);
  loc.textContent = locText.join(' · ');
  header.append(title, sev, rule, loc);
  card.appendChild(header);

  const msg = document.createElement('p');
  msg.className = 'vg-message';
  msg.textContent = f.description;
  card.appendChild(msg);

  if (f.snippet) {
    const pre = document.createElement('pre');
    pre.className = 'vg-snippet';
    pre.textContent = f.snippet;
    card.appendChild(pre);
  }

  if (f.remediation) {
    const det = document.createElement('details');
    det.className = 'vg-remediation';
    const sum = document.createElement('summary');
    sum.textContent = 'Remediation';
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'vg-rem-body';
    const why = document.createElement('p');
    const whyLabel = document.createElement('strong');
    whyLabel.textContent = 'Why:';
    why.append(whyLabel, ' ', f.remediation.why);
    const how = document.createElement('p');
    const howLabel = document.createElement('strong');
    howLabel.textContent = 'How:';
    how.append(howLabel, ' ', f.remediation.how);
    body.append(why, how);
    if (f.remediation.exampleFix) {
      const ex = document.createElement('pre');
      ex.className = 'vg-snippet';
      ex.textContent = f.remediation.exampleFix;
      body.appendChild(ex);
    }
    det.appendChild(body);
    card.appendChild(det);
  }

  return card;
}

/**
 * "These files are part of the PR and were never read."
 *
 * Deliberately lists the paths rather than only counting them. A count invites
 * the reader to assume the unread files were the uninteresting ones; the names
 * let them check. Capped at a readable number with the remainder counted, since
 * a 163-entry list would push the findings off the panel.
 */
function buildSkippedFilesBanner(skipped: string[]): HTMLElement {
  const banner = document.createElement('div');
  banner.className = 'vg-degradation';
  const SHOW = 10;
  const head = document.createElement('div');
  head.textContent =
    `⚠ ${skipped.length} changed file(s) were NOT scanned: GitHub did not render their diffs ` +
    `on this page (they sit behind "Load diff"). This review is PARTIAL — those files may ` +
    `contain issues nobody has looked at. Open them individually, or scan the branch with the CLI.`;
  banner.appendChild(head);
  const list = document.createElement('div');
  list.className = 'vg-file-meta';
  list.textContent =
    skipped.slice(0, SHOW).join(', ') +
    (skipped.length > SHOW ? `, +${skipped.length - SHOW} more` : '');
  banner.appendChild(list);
  return banner;
}

function buildDegradationBanner(degradations: ScanDegradation[]): HTMLElement {
  // A partial scan must never read as a clean one. This banner is what stops
  // "✓ No security issues found." from being shown for a file the scanner only
  // saw part of.
  const banner = document.createElement('div');
  banner.className = 'vg-degradation';
  // Counted in files: entries are deduplicated per file+kind, so a rule count
  // here would undercount how much was actually cut short.
  const files = new Set(degradations.map((d) => d.filePath).filter(Boolean));
  const scope = files.size > 1 ? ` (${files.size} files)` : '';
  // The banner names the CAUSE, and there are two distinct ones. It used to say
  // "a ReDoS guard stopped scanning before the end of the input" unconditionally,
  // which became false twice over once A1-LIMIT started routing match-limit
  // truncations through this channel: that bound is the per-file match cap, not
  // a ReDoS bound, and under it the input IS read to the end — only the reported
  // matches of one rule are capped. A reader told to look for a pathological
  // regex over a truncated input would find neither. Same basis as the CLI's
  // `appendDegradations` in apps/cli/src/format.ts.
  const causes = new Set(
    degradations.map((d) =>
      d.kind === 'match-limit'
        ? 'a per-file match limit capped how many matches were reported'
        : 'a ReDoS guard stopped scanning before the end of the input',
    ),
  );
  banner.textContent = `⚠ Partial scan${scope}: ${[...causes].join('; ')} — results may be incomplete.`;
  return banner;
}

/**
 * "A rule crashed and its findings are missing."
 *
 * `analyzer.scan` catches a throwing rule, records it in `ruleErrors` and lets
 * the rest of the scan finish — the right call, because a partial report beats
 * none. But the panel never read that field, so a rule that died contributed
 * zero findings and the result rendered as a green tick. `analyzer.ts` says as
 * much about the CLI ("renders `ruleErrors` under 'rule(s) errored and were
 * skipped — findings may be missing'"); this is the browser surface catching up.
 */
function buildRuleErrorBanner(errors: RuleError[]): HTMLElement {
  const banner = document.createElement('div');
  banner.className = 'vg-degradation';
  const ids = [...new Set(errors.map((e) => e.ruleId))];
  banner.textContent =
    `⚠ ${ids.length} rule(s) errored and were skipped — findings may be missing: ` +
    `${ids.slice(0, 6).join(', ')}${ids.length > 6 ? `, +${ids.length - 6} more` : ''}.`;
  return banner;
}

function renderFindings(
  findings: Finding[],
  degradations?: ScanDegradation[],
  ruleErrors?: RuleError[],
): void {
  findingsEl.replaceChildren();

  if (degradations?.length) {
    findingsEl.appendChild(buildDegradationBanner(degradations));
  }
  if (ruleErrors?.length) {
    findingsEl.appendChild(buildRuleErrorBanner(ruleErrors));
  }

  // An empty result is only CLEAN when nothing was cut short and nothing
  // crashed. Either one makes it merely unproven.
  const incomplete = Boolean(degradations?.length) || Boolean(ruleErrors?.length);

  if (findings.length === 0) {
    const empty = document.createElement('div');
    empty.className = incomplete ? 'vg-empty' : 'vg-empty vg-ok';
    empty.textContent = degradations?.length
      ? 'No issues found in the part of the input that was scanned.'
      : '✓ No security issues found.';
    findingsEl.appendChild(empty);
    return;
  }

  findingsEl.appendChild(buildSummaryBar(summarize(findings)));
  for (const f of findings) {
    findingsEl.appendChild(buildFindingCard(f));
  }
}

interface FileGroupResult {
  filePath: string;
  scanned: number; // lines scanned from the diff
  added: number;   // added lines among them
  findings: Finding[];
  /** D3 bounds that cut this file's scan short, if any. */
  degradations?: ScanDegradation[];
  /**
   * Why this file produced no findings for a reason OTHER than being clean.
   *
   * An empty `findings` array used to mean both "scanned, nothing found" and
   * "could not scan", and the panel rendered the same green tick for either. A
   * rule that throws, or a file the page never rendered, then looks exactly
   * like a file that passed. Set this and the group renders as unknown instead.
   */
  unscanned?: string;
}

function renderFileGroups(groups: FileGroupResult[], skippedFiles: string[] = []): void {
  findingsEl.replaceChildren();
  const allFindings = groups.flatMap((g) => g.findings);
  if (groups.length === 0 && skippedFiles.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'vg-empty';
    empty.textContent = 'No diff rows found.';
    findingsEl.appendChild(empty);
    return;
  }

  // Files the PAGE never rendered. This is the largest completeness gap in the
  // PR path and it is invisible from inside the scan: GitHub collapses the
  // diffs of a large PR behind "Load diff" and never puts their rows in the
  // DOM, so there is nothing to walk. Measured on rust-lang/rust#160102 — 284
  // changed files, 121 rendered, 163 collapsed, and scrolling to the bottom
  // does not change those numbers. Nothing the extension does can recover them
  // from this page; the only honest move is to say which ones went unread.
  if (skippedFiles.length > 0) {
    findingsEl.appendChild(buildSkippedFilesBanner(skippedFiles));
  }

  // Any partially-scanned file in the diff degrades the whole review, so the
  // banner goes above the summary rather than inside one file's section.
  const allDegradations = groups.flatMap((g) => g.degradations ?? []);
  if (allDegradations.length) {
    findingsEl.appendChild(buildDegradationBanner(allDegradations));
  }

  findingsEl.appendChild(buildSummaryBar(summarize(allFindings)));

  for (const g of groups) {
    const section = document.createElement('section');
    section.className = 'vg-file-group';

    const header = document.createElement('header');
    const path = document.createElement('span');
    path.className = 'vg-file-path';
    path.textContent = g.filePath;
    const meta = document.createElement('span');
    meta.className = 'vg-file-meta';
    meta.textContent = g.unscanned
      ? `${g.added} added · not scanned`
      : g.findings.length === 0
        ? `${g.added} added · 0 findings`
        : `${g.added} added · ${g.findings.length} finding(s)`;
    header.append(path, meta);
    section.appendChild(header);

    if (g.unscanned) {
      // Three states, not two: clean, findings, and unknown. The tick is
      // reserved for a file that was actually read.
      const warn = document.createElement('div');
      warn.className = 'vg-empty vg-degraded';
      warn.textContent = `⚠ Not scanned — ${g.unscanned}. This file's verdict is unknown.`;
      section.appendChild(warn);
    } else if (g.findings.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'vg-empty vg-ok';
      empty.textContent = '✓ No issues on the added lines.';
      section.appendChild(empty);
    } else {
      for (const f of g.findings) {
        section.appendChild(buildFindingCard(f, { showFilePath: false }));
      }
    }

    findingsEl.appendChild(section);
  }
}

// --- snippet scan ---------------------------------------------------------

function runSnippetScan(source: HistorySource, originLabel: string): void {
  const code = codeArea.value;
  if (!code.trim()) {
    setStatus('paste or extract some code first');
    return;
  }

  const langChoice = langSelect.value;
  const language = langChoice || detectLanguageFromContent(code) || 'javascript';

  const t0 = performance.now();
  try {
    const result = scan({
      targetType: 'snippet',
      mode: 'standard',
      content: code,
      language,
      filePath: 'snippet',
    });
    const ms = Math.round(performance.now() - t0);
    setStatus(`${result.findings.length} finding(s) in ${ms} ms · ${language}`);
    renderFindings(result.findings, result.degradations, result.ruleErrors);
    void recordHistory({
      source,
      origin: originLabel,
      language,
      summary: result.summary,
      findings: result.findings,
      codeForPreview: code,
      totalLines: code.split('\n').length,
    });
  } catch (err) {
    setStatus('scan failed');
    findingsEl.replaceChildren();
    const e = document.createElement('div');
    e.className = 'vg-error';
    e.textContent = err instanceof Error ? err.message : String(err);
    findingsEl.appendChild(e);
  }
}

/**
 * Scan extracted code blocks ONE AT A TIME, each in its own language.
 *
 * They used to be concatenated into a single snippet and scanned once, under a
 * single language. Two things went wrong with that, and both hid findings:
 *
 *  - A page mixing languages — an AI chat transcript, a tutorial, API docs —
 *    got ONE verdict under ONE language. Measured with the shipped browser
 *    core: a Python block calling `subprocess.call(..., shell=True)` and a JS
 *    block assigning to `innerHTML` report two findings when scanned
 *    separately and ONE when joined, whichever language is chosen. Joining
 *    always loses the other language's sinks.
 *  - The separator itself was `// --- block N ---`, a JavaScript comment
 *    injected into text that might be Python, where `//` is floor division.
 *
 * Blocks are their own unit of analysis, so they get the file-group renderer:
 * per-block language, per-block findings, and — since `FileGroupResult` carries
 * it — per-block "not scanned" when one throws.
 */
function scanExtractedBlocks(
  blocks: ExtractedCodeBlock[],
  originLabel: string,
  previewSource: string,
): void {
  const t0 = performance.now();
  const results = scanBlocks(blocks, {
    scan,
    detectLanguageFromContent,
    fallbackLanguage: langSelect.value || undefined,
  });
  const groups: FileGroupResult[] = results.map((r) => ({
    filePath: r.label,
    scanned: r.lineCount,
    added: r.lineCount,
    findings: r.findings,
    ...(r.degradations ? { degradations: r.degradations } : {}),
    ...(r.unscanned ? { unscanned: r.unscanned } : {}),
  }));

  const ms = Math.round(performance.now() - t0);
  const all = groups.flatMap((g) => g.findings);
  setStatus(`${all.length} finding(s) across ${blocks.length} block(s) in ${ms} ms`);
  renderFileGroups(groups);

  void recordHistory({
    source: 'page-extract',
    origin: originLabel,
    language: groups.length === 1 ? undefined : 'multi',
    summary: summarize(all),
    findings: all,
    codeForPreview: previewSource,
    totalLines: previewSource.split('\n').length,
    fileCount: blocks.length,
  });
}

// --- GitHub PR diff scan --------------------------------------------------

async function runGithubDiffScan(): Promise<void> {
  setStatus('reading diff…');
  scanPrBtn.disabled = true;
  try {
    const req: RequestGithubDiffMessage = { type: 'vibeguard.extractGithubDiff' };
    const reply = (await chrome.runtime.sendMessage(req)) as GithubDiffResultMessage | undefined;
    if (!reply || reply.type !== 'vibeguard.githubDiffResult') {
      setStatus('no response from background');
      return;
    }
    if (reply.error && reply.files.length === 0) {
      setStatus(reply.error);
      findingsEl.replaceChildren();
      const e = document.createElement('div');
      e.className = 'vg-empty';
      e.textContent = reply.error;
      findingsEl.appendChild(e);
      return;
    }

    setOrigin(`github-pr-diff: ${reply.origin}`);
    // Don't dump the diff into the textarea — it's multi-file and we don't
    // want the user to think editing it will rescan that diff.
    codeArea.value = '';

    const t0 = performance.now();
    const groups = scanDiffFiles(reply.files);
    const ms = Math.round(performance.now() - t0);
    const totalFindings = groups.reduce((n, g) => n + g.findings.length, 0);
    // The count has to name the DENOMINATOR when it is not the whole PR.
    // "8 finding(s) across 121 file(s)" reads as a complete review of a PR that
    // changes 284 — the reviewer has no way to know 163 were never read.
    const skipped = reply.skippedFiles ?? [];
    const scope = skipped.length
      ? `${reply.files.length} of ${reply.files.length + skipped.length} file(s)`
      : `${reply.files.length} file(s)`;
    setStatus(`${totalFindings} finding(s) across ${scope} in ${ms} ms`);
    renderFileGroups(groups, skipped);

    const allFindings = groups.flatMap((g) => g.findings);
    const previewPaths = reply.files
      .slice(0, 5)
      .map((f) => f.filePath)
      .join(', ');
    const previewSuffix = reply.files.length > 5 ? `, +${reply.files.length - 5} more` : '';
    void recordHistory({
      source: 'github-pr-diff',
      origin: reply.origin,
      language: 'multi',
      summary: summarize(allFindings),
      findings: allFindings,
      codeForPreview: `${reply.files.length} file(s): ${previewPaths}${previewSuffix}`,
      totalLines: reply.files.reduce((n, f) => n + f.lines.length, 0),
      fileCount: reply.files.length,
    });
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err));
  } finally {
    scanPrBtn.disabled = false;
  }
}

function scanDiffFiles(files: ParsedDiffFile[]): FileGroupResult[] {
  const groups: FileGroupResult[] = [];
  for (const file of files) {
    const content = reconstructPseudoContent(file);
    const added = addedLineSet(file);
    if (content.length === 0 || added.size === 0) {
      groups.push({
        filePath: file.filePath,
        scanned: file.lines.length,
        added: added.size,
        findings: [],
      });
      continue;
    }
    const language = file.language ?? languageFromPath(file.filePath);
    let result;
    try {
      result = scan({
        targetType: 'diff',
        mode: 'standard',
        content,
        language,
        filePath: file.filePath,
      });
    } catch (err) {
      // NOT the same as "no issues". The analyzer failed on this file, so its
      // verdict is unknown; reporting an empty finding list without saying so
      // turns an engine failure into a clean bill of health.
      groups.push({
        filePath: file.filePath,
        scanned: file.lines.length,
        added: added.size,
        findings: [],
        unscanned: `scan failed: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }
    const overlapping = result.findings.filter((f) => {
      const start = f.startLine ?? 0;
      if (!start) return false;
      const end = f.endLine ?? start;
      for (let ln = start; ln <= end; ln++) {
        if (added.has(ln)) return true;
      }
      return false;
    });
    groups.push({
      filePath: file.filePath,
      scanned: file.lines.length,
      added: added.size,
      findings: overlapping,
      // Carried per file so the PR-diff view can say a file was only partly
      // scanned. Without it a truncated diff review reads as a clean one — the
      // same gap that made the snippet path misleading before the banner.
      degradations: result.degradations,
    });
  }
  return groups;
}

// --- history --------------------------------------------------------------

interface RecordHistoryInput {
  source: HistorySource;
  origin?: string;
  language?: string;
  summary: ScanSummary;
  findings: Finding[];
  codeForPreview: string;
  totalLines: number;
  fileCount?: number;
}

async function recordHistory(input: RecordHistoryInput): Promise<void> {
  try {
    const entry = buildHistoryEntry(input);
    const next = await appendHistory(entry);
    renderHistory(next);
  } catch (err) {
    console.warn('[vibeguard] history save failed', err);
  }
}

function fmtTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function buildHistoryEntryNode(entry: HistoryEntry): HTMLElement {
  const wrap = document.createElement('article');
  wrap.className = 'vg-history-entry';

  const header = document.createElement('header');
  const when = document.createElement('span');
  when.className = 'vg-h-when';
  when.textContent = fmtTime(entry.timestamp);
  const source = document.createElement('span');
  source.className = 'vg-h-source';
  source.textContent = entry.source;
  const origin = document.createElement('span');
  origin.className = 'vg-h-origin';
  origin.textContent = entry.origin ?? entry.language ?? '';
  header.append(when, source, origin);
  wrap.appendChild(header);

  const summaryBar = document.createElement('div');
  summaryBar.className = 'vg-h-summary';
  let any = false;
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    const n = entry.summary[sev];
    if (!n) continue;
    any = true;
    const tag = document.createElement('span');
    tag.className = 'vg-h-sev';
    tag.dataset.severity = sev;
    tag.textContent = `${sev}: ${n}`;
    summaryBar.appendChild(tag);
  }
  if (!any) {
    const ok = document.createElement('span');
    ok.className = 'vg-h-empty vg-ok';
    ok.textContent = '✓ no issues';
    summaryBar.appendChild(ok);
  }
  if (entry.fileCount && entry.fileCount > 1) {
    const fc = document.createElement('span');
    fc.className = 'vg-h-sev';
    fc.textContent = `${entry.fileCount} files`;
    summaryBar.appendChild(fc);
  }
  wrap.appendChild(summaryBar);

  if (entry.codePreview) {
    const pre = document.createElement('pre');
    pre.className = 'vg-h-preview';
    pre.textContent = entry.codePreview;
    wrap.appendChild(pre);
  }

  if (entry.findings.length > 0) {
    const det = document.createElement('details');
    const sum = document.createElement('summary');
    sum.textContent = `Findings (${entry.findings.length})`;
    det.appendChild(sum);
    const ul = document.createElement('ul');
    for (const f of entry.findings) {
      const li = document.createElement('li');
      const parts: string[] = [];
      parts.push(`[${f.severity}] ${f.title}`);
      parts.push(`(${f.ruleId})`);
      if (f.filePath) parts.push(f.filePath);
      if (f.startLine) parts.push(`L${f.startLine}`);
      li.textContent = parts.join(' ');
      ul.appendChild(li);
    }
    det.appendChild(ul);
    wrap.appendChild(det);
  }

  return wrap;
}

function renderHistory(entries: HistoryEntry[]): void {
  historyCountEl.textContent = entries.length === 0 ? '' : `(${entries.length})`;
  historyListEl.replaceChildren();
  if (entries.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'vg-h-empty';
    empty.textContent = 'No history yet.';
    historyListEl.appendChild(empty);
    return;
  }
  for (const entry of entries) {
    historyListEl.appendChild(buildHistoryEntryNode(entry));
  }
}

historyClearBtn.addEventListener('click', async (ev) => {
  // The Clear button lives inside <summary>; stop the click from toggling
  // the <details>.
  ev.preventDefault();
  ev.stopPropagation();
  await clearHistory();
  renderHistory([]);
});

void loadHistory().then(renderHistory).catch(() => renderHistory([]));

// --- wire buttons ---------------------------------------------------------

scanBtn.addEventListener('click', () => runSnippetScan('paste', 'snippet'));

clearBtn.addEventListener('click', () => {
  codeArea.value = '';
  setStatus('');
  setOrigin('paste code or extract from page');
  findingsEl.replaceChildren();
});

extractBtn.addEventListener('click', async () => {
  setStatus('extracting…');
  try {
    const req: RequestExtractMessage = { type: 'vibeguard.extractFromActiveTab' };
    const reply = (await chrome.runtime.sendMessage(req)) as ExtractResultMessage | undefined;
    if (!reply || reply.type !== 'vibeguard.extractResult') {
      setStatus('no response from background');
      return;
    }
    if (reply.error) {
      setStatus(`extract failed: ${reply.error}`);
      return;
    }
    if (reply.blocks.length === 0) {
      setStatus('no <pre><code> blocks found on page');
      return;
    }

    // The textarea still shows everything, joined, so the user can see what was
    // taken off the page. The SCAN no longer works from that joined text.
    const joined = reply.blocks
      .map((b, i) => `// --- block ${i + 1}${b.language ? ` (${b.language})` : ''} ---\n${b.text}`)
      .join('\n\n');

    codeArea.value = joined;
    setOrigin(reply.origin);

    // If every block agrees on a language, reflect that in the picker.
    const langs = new Set(reply.blocks.map((b) => b.language).filter(Boolean));
    if (langs.size === 1) {
      const lang = [...langs][0]!;
      const opt = Array.from(langSelect.options).find((o) => o.value === lang);
      if (opt) langSelect.value = lang;
    }

    setStatus(`extracted ${reply.blocks.length} block(s)`);
    scanExtractedBlocks(reply.blocks, reply.origin, joined);
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err));
  }
});

scanPrBtn.addEventListener('click', () => {
  void runGithubDiffScan();
});

// --- async pushes from background ---------------------------------------

chrome.runtime.onMessage.addListener((message: VibeGuardMessage) => {
  if (message.type !== 'vibeguard.pushCode') return;
  applyPush(message);
});

function applyPush(msg: PushCodeMessage): void {
  codeArea.value = msg.code;
  const originLabel = `${msg.source}: ${msg.origin ?? ''}`.trim();
  setOrigin(originLabel);
  runSnippetScan(msg.source as HistorySource, msg.origin ?? msg.source);
}

// If the panel was opened *by* a context-menu click, the push may have raced
// us. Drain any pending push from session storage.
chrome.storage?.session
  ?.get('vibeguard.pendingPush')
  .then((rec) => {
    const pending = rec?.['vibeguard.pendingPush'] as PushCodeMessage | undefined;
    if (pending && pending.type === 'vibeguard.pushCode') {
      applyPush(pending);
      chrome.storage.session.remove('vibeguard.pendingPush').catch(() => {});
    }
  })
  .catch(() => {});
