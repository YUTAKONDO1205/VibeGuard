/**
 * The five /go/* redirect targets — the single definition.
 *
 * Both consumers import this file: the Astro pages that render links to
 * /go/<channel>, and worker/index.ts, which turns the path into a 302. The
 * point is that no URL for a distribution channel is written twice anywhere in
 * site/, so there is no second copy to drift.
 *
 * The authority for these URLs is the Install table in the repository's
 * README.md. scripts/site-copy-lint.mjs (rule R5) reads both and fails the
 * build if they disagree, which is what makes "single definition" a checked
 * property rather than a comment.
 */

export type Channel = 'vscode' | 'openvsx' | 'chrome' | 'action' | 'github';

/**
 * The allowlist. worker/index.ts answers 404 for any /go/ path that is not a
 * key here — an allowlist rather than a pattern, so a typo in a link becomes a
 * 404 instead of an open redirect.
 */
export const GO_TARGETS: Record<Channel, string> = {
  vscode: 'https://marketplace.visualstudio.com/items?itemName=yutakondo.vibeguard-aicoding',
  openvsx: 'https://open-vsx.org/extension/yutakondo/vibeguard-aicoding',
  chrome: 'https://chromewebstore.google.com/detail/ggdiodcjmdnkhncnpafcjokgonhmhbdf',
  action: 'https://github.com/marketplace/actions/vibe-guard-aicoding',
  github: 'https://github.com/YUTAKONDO1205/VibeGuard',
};

export const CHANNELS: Channel[] = ['vscode', 'openvsx', 'chrome', 'action'];

/**
 * Human-facing names for the four installable channels. `github` is absent on
 * purpose: it is a repository link in the footer, not a way to install
 * anything, and giving it a card here is how it would drift into one.
 */
export const CHANNEL_LABELS: Record<Channel, string> = {
  vscode: 'VS Code Marketplace',
  openvsx: 'Open VSX Registry',
  chrome: 'Chrome Web Store',
  action: 'GitHub Marketplace (Action)',
  github: 'GitHub repository',
};

export const goHref = (channel: Channel): string => `/go/${channel}`;

export const isChannel = (value: string): value is Channel =>
  Object.prototype.hasOwnProperty.call(GO_TARGETS, value);
