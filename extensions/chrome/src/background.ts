// VibeGuard background service worker.
//
// Responsibilities:
//   1. Open the side panel when the toolbar action is clicked.
//   2. Register a "Scan with VibeGuard" context menu on text selections that
//      forwards the selection to the side panel.
//   3. Relay extraction requests from the side panel:
//      - generic <pre><code> walk on any page
//      - GitHub PR diff walk on github.com/.../pull/... pages

import type { ParsedDiffFile, DiffLine } from './shared/diff-reconstruct.js';
import type {
  ExtractedBlock,
  ExtractResultMessage,
  GithubDiffResultMessage,
  PushCodeMessage,
  VibeGuardMessage,
} from './shared/messages.js';

const CONTEXT_MENU_ID = 'vibeguard.scanSelection';

// --- side panel wiring ---------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: CONTEXT_MENU_ID,
    title: 'Scan with VibeGuard',
    contexts: ['selection'],
  });

  // Open side panel when the action is clicked.
  if (chrome.sidePanel?.setPanelBehavior) {
    chrome.sidePanel
      .setPanelBehavior({ openPanelOnActionClick: true })
      .catch((err) => console.warn('[vibeguard] setPanelBehavior failed', err));
  }
});

chrome.action.onClicked.addListener(async (tab) => {
  if (tab.windowId === undefined) return;
  try {
    await chrome.sidePanel.open({ windowId: tab.windowId });
  } catch (err) {
    console.warn('[vibeguard] sidePanel.open failed', err);
  }
});

// --- context-menu → side panel ------------------------------------------

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== CONTEXT_MENU_ID) return;
  const selection = info.selectionText ?? '';
  if (!selection.trim()) return;

  if (tab?.windowId !== undefined) {
    try {
      await chrome.sidePanel.open({ windowId: tab.windowId });
    } catch {
      /* ignore — user can still open the panel manually */
    }
  }

  const msg: PushCodeMessage = {
    type: 'vibeguard.pushCode',
    source: 'context-menu',
    code: selection,
    origin: tab?.url ?? 'selection',
  };
  // The side panel listens on runtime.onMessage.
  chrome.runtime.sendMessage(msg).catch(() => {
    // No receiver yet; the panel will pick up the latest pending push from
    // session storage when it loads.
    chrome.storage.session.set({ 'vibeguard.pendingPush': msg }).catch(() => {});
  });
});

// --- generic code extraction --------------------------------------------

/**
 * Runs in the *page* context via scripting.executeScript. Must be self-
 * contained — no closures, no shared imports — because it is serialized.
 */
function collectCodeBlocksInPage(): ExtractedBlock[] {
  const out: ExtractedBlock[] = [];
  const seen = new Set<Element>();

  // Prefer <pre><code> structures (GitHub, Stack Overflow, ChatGPT).
  document.querySelectorAll('pre code, pre').forEach((el) => {
    if (seen.has(el)) return;
    // If <pre> contains a <code>, prefer the <code> child to avoid double
    // capture.
    if (el.tagName === 'PRE' && el.querySelector('code')) {
      return;
    }
    seen.add(el);

    const text = (el as HTMLElement).innerText ?? el.textContent ?? '';
    if (!text.trim()) return;

    let language: string | undefined;
    const classes = (el.className || '').split(/\s+/);
    for (const c of classes) {
      const m = /^(?:language-|lang-|hljs\s+language-)([a-z0-9+#-]+)$/i.exec(c);
      if (m) {
        language = m[1].toLowerCase();
        break;
      }
    }
    out.push({ text, language });
  });

  return out;
}

// --- GitHub PR diff extraction ------------------------------------------

/**
 * Runs in the page context. Walks GitHub's diff-table DOM and returns one
 * ParsedDiffFile per file block. Self-contained — types referenced here
 * must be inlined or imported as `type` only (erased at runtime).
 *
 * GitHub serves two layouts depending on rollout:
 *
 *   Classic table (most stable as of 2026-05):
 *     <div class="file" data-path="src/foo.ts">
 *       <table class="diff-table">
 *         <tr>
 *           <td class="blob-num blob-num-addition" data-line-number="42">42</td>
 *           <td class="blob-code blob-code-addition">
 *             <span class="blob-code-inner">...code...</span>
 *           </td>
 *         </tr>
 *         ...context, deletion, addition rows
 *       </table>
 *     </div>
 *
 * For each row we look at the last blob-code-* cell (addition or context),
 * then read the new-side line number from the last blob-num td that has
 * data-line-number. Deletion-only rows are ignored.
 */
function collectGithubDiffInPage(): { files: ParsedDiffFile[]; error?: string } {
  // Only run on PR pages — Issues / Commits also use blob-* classes but the
  // diff semantics differ.
  if (!/\/pull\/\d+/.test(location.pathname)) {
    return { files: [], error: 'Not on a GitHub PR page (need /pull/<n>).' };
  }

  const files: ParsedDiffFile[] = [];

  // GitHub wraps each file in a div with data-path; fall back to data-tagsearch-path
  // (rolled out alongside the search overhaul).
  const fileBlocks = Array.from(
    document.querySelectorAll<HTMLElement>('[data-path], [data-tagsearch-path]'),
  ).filter((el) => el.querySelector('table.diff-table, table.js-file-line-container'));

  for (const block of fileBlocks) {
    const filePath =
      block.getAttribute('data-path') ?? block.getAttribute('data-tagsearch-path') ?? '';
    if (!filePath) continue;

    const tables = block.querySelectorAll<HTMLTableElement>(
      'table.diff-table, table.js-file-line-container',
    );
    const lines: DiffLine[] = [];
    const seenLineNumbers = new Set<number>();

    for (const table of tables) {
      const rows = table.querySelectorAll<HTMLTableRowElement>('tr');
      for (const row of rows) {
        // The visible code cell. blob-code-addition / -context wins; deletion
        // rows are ignored.
        const additionCell = row.querySelector<HTMLElement>('td.blob-code.blob-code-addition');
        const contextCell = !additionCell
          ? row.querySelector<HTMLElement>('td.blob-code.blob-code-context')
          : null;
        const cell = additionCell ?? contextCell;
        if (!cell) continue;
        if (cell.classList.contains('blob-code-hunk')) continue; // hunk header rows

        // The new-side line number: last blob-num td in the row that exposes
        // data-line-number. For addition rows the addition cell is what we
        // want; for context rows there are two num cells (old, new) and the
        // new one is the second.
        const numCells = row.querySelectorAll<HTMLElement>('td.blob-num[data-line-number]');
        // For addition rows in unified view, pick the blob-num-addition cell;
        // for context rows, pick the last (new-side) cell. Walking backwards
        // and skipping deletion cells handles both layouts.
        let ln: number | null = null;
        for (let i = numCells.length - 1; i >= 0; i--) {
          const c = numCells[i]!;
          if (c.classList.contains('blob-num-deletion')) continue;
          const raw = c.getAttribute('data-line-number');
          if (!raw) continue;
          const parsed = Number.parseInt(raw, 10);
          if (Number.isFinite(parsed) && parsed > 0) {
            ln = parsed;
            break;
          }
        }
        if (ln === null) continue;
        if (seenLineNumbers.has(ln)) continue; // split view duplicates
        seenLineNumbers.add(ln);

        // Prefer the inner span to avoid the "+" marker GitHub injects via CSS
        // ::before. innerText preserves visible whitespace.
        const inner = cell.querySelector<HTMLElement>('.blob-code-inner') ?? cell;
        const text = (inner.innerText ?? inner.textContent ?? '').replace(/​/g, '');
        lines.push({ ln, text, added: !!additionCell });
      }
    }

    if (lines.length === 0) continue;

    // Language hint from extension; analyzer will re-detect anyway.
    const dot = filePath.lastIndexOf('.');
    const ext = dot >= 0 ? filePath.slice(dot + 1).toLowerCase() : '';
    const langMap: Record<string, string> = {
      js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
      ts: 'typescript', tsx: 'typescript',
      py: 'python', go: 'go', java: 'java', rb: 'ruby', php: 'php', cs: 'csharp',
    };
    files.push({ filePath, language: langMap[ext], lines });
  }

  if (files.length === 0) {
    return {
      files: [],
      error:
        'No diff rows found. Open the "Files changed" tab on a PR (the classic table view).',
    };
  }

  return { files };
}

// --- message routing -----------------------------------------------------

chrome.runtime.onMessage.addListener((message: VibeGuardMessage, _sender, sendResponse) => {
  if (message.type === 'vibeguard.extractFromActiveTab') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) {
          const reply: ExtractResultMessage = {
            type: 'vibeguard.extractResult',
            origin: 'unknown',
            blocks: [],
            error: 'No active tab',
          };
          sendResponse(reply);
          return;
        }
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: false },
          func: collectCodeBlocksInPage,
        });
        const blocks = (results[0]?.result as ExtractedBlock[] | undefined) ?? [];
        const reply: ExtractResultMessage = {
          type: 'vibeguard.extractResult',
          origin: tab.url ?? 'active tab',
          blocks,
        };
        sendResponse(reply);
      } catch (err) {
        const reply: ExtractResultMessage = {
          type: 'vibeguard.extractResult',
          origin: 'active tab',
          blocks: [],
          error: err instanceof Error ? err.message : String(err),
        };
        sendResponse(reply);
      }
    })();
    return true; // async response
  }

  if (message.type === 'vibeguard.extractGithubDiff') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) {
          const reply: GithubDiffResultMessage = {
            type: 'vibeguard.githubDiffResult',
            origin: 'unknown',
            files: [],
            error: 'No active tab',
          };
          sendResponse(reply);
          return;
        }
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: false },
          func: collectGithubDiffInPage,
        });
        const out = results[0]?.result as { files: ParsedDiffFile[]; error?: string } | undefined;
        const reply: GithubDiffResultMessage = {
          type: 'vibeguard.githubDiffResult',
          origin: tab.url ?? 'active tab',
          files: out?.files ?? [],
          error: out?.error,
        };
        sendResponse(reply);
      } catch (err) {
        const reply: GithubDiffResultMessage = {
          type: 'vibeguard.githubDiffResult',
          origin: 'active tab',
          files: [],
          error: err instanceof Error ? err.message : String(err),
        };
        sendResponse(reply);
      }
    })();
    return true;
  }

  return undefined;
});
