/**
 * The canonical URL for a page — the one form of its address the site claims.
 *
 * WHY THIS IS NOT JUST `new URL(Astro.url.pathname, Astro.site)`
 *
 * That is what the layouts did, and it was wrong on every page. `build.format`
 * is `'file'`, so Astro writes `install.html` rather than `install/index.html`
 * — which is what makes `/install` the address instead of `/install/`. The cost
 * is that during the build `Astro.url.pathname` is the OUTPUT FILE's path,
 * `/install.html`, not the URL anyone visits.
 *
 * So the six pages were each publishing a canonical pointing at `<page>.html`
 * while sitemap.xml listed the extensionless form and every internal link used
 * it too. Canonical is the stronger of those signals, so the site was
 * explicitly nominating the form it had decided not to use. Cloudflare serves
 * both, which is exactly what makes this the kind of mistake nobody notices:
 * every URL involved returns 200.
 *
 * Normalising here rather than in each layout means the two layouts cannot
 * drift, and the rule is stated once next to its reason.
 */

/**
 * `/install.html` -> `/install`, `/index.html` -> `/`,
 * `/research/compiler.html` -> `/research/compiler`.
 *
 * Anything already extensionless passes through untouched, so this stays
 * correct if `build.format` is ever changed back to `'directory'`.
 */
export function canonicalPath(pathname: string): string {
  const withoutExt = pathname.replace(/\.html$/, '');
  if (withoutExt === '/index') return '/';
  return withoutExt.replace(/\/index$/, '/');
}

/**
 * Absolute canonical URL, or `undefined` when the site has no origin yet.
 *
 * Undefined is a real answer rather than a fallback: before a domain exists
 * there is no absolute URL to name, and emitting a guessed one would point
 * search engines at somewhere that does not answer.
 */
export function canonicalUrl(site: URL | undefined, pathname: string): string | undefined {
  return site ? new URL(canonicalPath(pathname), site).href : undefined;
}
