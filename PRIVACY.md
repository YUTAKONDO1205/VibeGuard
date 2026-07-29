# VibeGuard Privacy Policy

Last updated: 2026-07-29

## What we collect

**Nothing.** VibeGuard does not collect, transmit, store on our servers, sell,
or share any data about you, your browsing, or the source code you analyze.

## How VibeGuard handles your code

- All security analysis runs **locally** inside your browser (Chrome extension)
  or on your machine (CLI / GitHub Action).
- Source code you paste, select, or extract is analysed in memory and is
  **never sent off-device** by VibeGuard itself.
- Two places keep parts of your code on your own device, and you should know
  about both:
  - **Scan reports.** A finding carries the matched line as `snippet` and the
    matched text as `evidence`. When you ask the CLI or the GitHub Action to
    write a report (`--out`, or a `format` of `json` / `sarif` / `markdown`),
    those fields go into that file. If you then publish the report — for
    example by uploading SARIF to GitHub code scanning — whatever the finding
    matched travels with it. Treat a scan report as sensitive as the code it
    describes.
  - **Chrome scan history.** See "Scan history stored on your device" below.
- The Chrome extension uses `chrome.storage.session` as a short-lived
  hand-off between the service worker and the side panel for context-menu
  scans. That data is read once and discarded; it does not persist across
  browser sessions.

### Scan history stored on your device

The Chrome extension also keeps a **scan history** so the side panel can show
what you scanned recently. This is stored in `chrome.storage.local`, which
**persists across browser sessions** until you clear it or remove the
extension. Nothing in it leaves your device.

Each history entry holds:

- the scan summary (counts by severity) and a compact finding list
  (rule ID, title, severity, file path, start line — no snippets, no
  remediation text);
- **`codePreview`: the first 200 characters of the text you scanned, stored
  verbatim.** For a pasted snippet or an extracted code block this is your
  raw code. If a credential appears in those first 200 characters, it is
  stored as written. For pull-request scans the preview is a file-name list,
  not code;
- the origin label (page URL, PR URL, or `snippet`), a timestamp, and line
  counts.

At most 50 entries are kept; older ones are dropped. Clear them at any time
with the **Clear** button in the side panel's History section, which deletes
the whole `vibeguard.history` key. Uninstalling the extension also removes it.

If you do not want scan input persisted at all, clear the history after
scanning, or avoid scanning secrets into the side panel.

## Network access

The extension does not make any network requests. It works fully offline.

## Permissions and why we need them

- `activeTab`, `scripting`: read code from the active tab when you explicitly
  invoke "Extract code blocks" or right-click "Scan with VibeGuard".
- `contextMenus`: register the right-click menu entry.
- `sidePanel`: open the analysis UI as a Chrome side panel.
- `storage`: hand off a snippet from the background worker to the side panel
  (`storage.session`), and keep the on-device scan history described above
  (`storage.local`).
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
