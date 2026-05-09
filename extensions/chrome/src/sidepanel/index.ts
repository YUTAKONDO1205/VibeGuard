// VibeGuard side panel UI.
//
// Pulls findings out of @vibeguard/analyzer-core (browser subpath, no fs)
// and renders them.  Receives async pushes from:
//   - context-menu "Scan with VibeGuard"  (background → runtime.sendMessage)
//   - "Extract from page" button          (panel → background → executeScript)

import { scan, detectLanguageFromContent } from '@vibeguard/analyzer-core/browser';
import type { Finding } from '@vibeguard/findings-schema';
import type {
  ExtractResultMessage,
  PushCodeMessage,
  RequestExtractMessage,
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
const statusEl = $<HTMLSpanElement>('#status');
const originEl = $<HTMLParagraphElement>('#origin');
const findingsEl = $<HTMLElement>('#findings');

function setStatus(msg: string): void {
  statusEl.textContent = msg;
}

function setOrigin(origin: string): void {
  originEl.textContent = origin;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderFindings(findings: Finding[]): void {
  findingsEl.replaceChildren();

  if (findings.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'vg-empty';
    empty.textContent = 'No findings.';
    findingsEl.appendChild(empty);
    return;
  }

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const summary = document.createElement('div');
  summary.className = 'vg-summary';
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    if (counts[sev]) {
      const tag = document.createElement('span');
      tag.textContent = `${sev}: ${counts[sev]}`;
      summary.appendChild(tag);
    }
  }
  findingsEl.appendChild(summary);

  for (const f of findings) {
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
    loc.textContent = f.startLine ? `L${f.startLine}` : '';
    header.append(title, sev, rule, loc);
    card.appendChild(header);

    const msg = document.createElement('p');
    msg.className = 'vg-message';
    msg.textContent = f.description;
    card.appendChild(msg);

    if (f.snippet) {
      const pre = document.createElement('pre');
      pre.className = 'vg-snippet';
      pre.innerHTML = escapeHtml(f.snippet);
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
      why.innerHTML = `<strong>Why:</strong> ${escapeHtml(f.remediation.why)}`;
      const how = document.createElement('p');
      how.innerHTML = `<strong>How:</strong> ${escapeHtml(f.remediation.how)}`;
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

    findingsEl.appendChild(card);
  }
}

function runScan(): void {
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
    renderFindings(result.findings);
  } catch (err) {
    setStatus('scan failed');
    findingsEl.replaceChildren();
    const e = document.createElement('div');
    e.className = 'vg-error';
    e.textContent = err instanceof Error ? err.message : String(err);
    findingsEl.appendChild(e);
  }
}

scanBtn.addEventListener('click', runScan);

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

    // Concatenate all blocks separated by a marker so a single scan can cover
    // the page; the line numbers reported will reference the joined text.
    const joined = reply.blocks
      .map((b, i) => `// --- block ${i + 1}${b.language ? ` (${b.language})` : ''} ---\n${b.text}`)
      .join('\n\n');

    codeArea.value = joined;
    setOrigin(reply.origin);

    // If every block agrees on a language, prefer that.
    const langs = new Set(reply.blocks.map((b) => b.language).filter(Boolean));
    if (langs.size === 1) {
      const lang = [...langs][0]!;
      const opt = Array.from(langSelect.options).find((o) => o.value === lang);
      if (opt) langSelect.value = lang;
    }

    setStatus(`extracted ${reply.blocks.length} block(s)`);
    runScan();
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err));
  }
});

// Context-menu pushes from the background service worker.
chrome.runtime.onMessage.addListener((message: VibeGuardMessage) => {
  if (message.type !== 'vibeguard.pushCode') return;
  applyPush(message);
});

function applyPush(msg: PushCodeMessage): void {
  codeArea.value = msg.code;
  setOrigin(`${msg.source}: ${msg.origin ?? ''}`.trim());
  runScan();
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
