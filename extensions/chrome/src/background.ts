// VibeGuard background service worker.
//
// Responsibilities:
//   1. Open the side panel when the toolbar action is clicked.
//   2. Register a "Scan with VibeGuard" context menu on text selections that
//      forwards the selection to the side panel.
//   3. Relay extraction requests from the side panel: when asked, run a
//      content-script-style function in the active tab to collect <pre><code>
//      blocks and reply with the result.

import type {
  ExtractedBlock,
  ExtractResultMessage,
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

// --- code extraction -----------------------------------------------------

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

chrome.runtime.onMessage.addListener((message: VibeGuardMessage, _sender, sendResponse) => {
  if (message.type !== 'vibeguard.extractFromActiveTab') return;

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

  // async response
  return true;
});
