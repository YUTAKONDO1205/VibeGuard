# VibeGuard Privacy Policy

Last updated: 2026-07-04

## What we collect

**Nothing.** VibeGuard does not collect, transmit, store on our servers, sell,
or share any data about you, your browsing, or the source code you analyze.

## How VibeGuard handles your code

- All security analysis runs **locally** inside your browser (Chrome extension)
  or on your machine (CLI / GitHub Action).
- Source code you paste, select, or extract is processed in memory and is
  **never sent off-device**.
- The Chrome extension uses `chrome.storage.session` only as a short-lived
  hand-off between the service worker and the side panel for context-menu
  scans. The data is read once and discarded; it does not persist across
  browser sessions.

## Network access

The extension does not make any network requests. It works fully offline.

## Permissions and why we need them

- `activeTab`, `scripting`: read code from the active tab when you explicitly
  invoke "Extract code blocks" or right-click "Scan with VibeGuard".
- `contextMenus`: register the right-click menu entry.
- `sidePanel`: open the analysis UI as a Chrome side panel.
- `storage`: hand off a snippet from the background worker to the side panel.
- Host permission `<all_urls>`: necessary so the user can scan code from any
  site. Page content is only read when the user explicitly initiates a scan.

## Third parties

None. No analytics, no telemetry, no remote logging, no ad networks.

## Children's privacy

VibeGuard does not knowingly collect any personal information from anyone,
including children under 13.

## Changes to this policy

If this policy ever changes, the new version will be committed to this
repository and the "Last updated" date above will reflect the change.

## Contact

Issues and questions: https://github.com/YUTAKONDO1205/VibeGuard/issues
