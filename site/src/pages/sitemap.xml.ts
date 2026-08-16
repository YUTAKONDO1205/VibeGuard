// /sitemap.xml — the six content pages, and nothing else.
//
// Written by hand rather than with @astrojs/sitemap for two reasons. The
// integration would be a dependency added to a site that has exactly one, and
// it discovers routes by crawling the build output — which would find
// /sitemap.xml itself and the 404 page, and would have found /go/* if those had
// ever been routes. The list of indexable pages is a decision, not a filesystem
// fact, so it is stated here where it can be read.
//
// /go/* must never appear below. Those five paths are counted redirects to
// extension stores; indexing them lets a visitor land on a store without
// passing /install, and lets a crawler inflate the click count. robots.txt
// disallows them and the Worker sends X-Robots-Tag: noindex on the responses.
import type { APIRoute } from 'astro';

/**
 * The frozen six. Adding a seventh means editing the sitemap in the same
 * commit as the page, which is the intended amount of friction: the site's
 * whole shape argument is that six pages is the complete site, and a page that
 * nobody thought to list here is a page nobody decided to add.
 */
const PAGES = ['/', '/install', '/rules', '/research/compiler', '/news', '/privacy'] as const;

/**
 * No <lastmod>. The only value available at build time is "when the build
 * ran", which changes on every deploy regardless of whether the page did —
 * that is a lie told to a crawler on a schedule. No <changefreq> or <priority>
 * either: both are hints search engines have long documented as ignored, and
 * an ignored field is a field that can be wrong without consequence, which is
 * the kind of field that ends up wrong.
 */
const escapeXml = (value: string): string =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export const GET: APIRoute = ({ site }) => {
  // `site` comes from astro.config.mjs, which sets it from SITE_ORIGIN and
  // leaves it undefined while no domain is registered. The sitemap protocol
  // wants absolute URLs, so the honest output in that state is not a guessed
  // origin — it is relative locs plus a comment saying why, which a person
  // reading the deployed file can act on. Once SITE_ORIGIN is set, the same
  // code emits a fully conformant sitemap with no edit here.
  const locs = PAGES.map((path) => escapeXml(site ? new URL(path, site).href : path));

  const provenance = site
    ? ''
    : '\n  <!-- Relative locations: this deployment has no configured origin, so an\n       absolute URL here would be a guess. Set SITE_ORIGIN at build time and\n       these become absolute. -->';

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${provenance}
${locs.map((loc) => `  <url><loc>${loc}</loc></url>`).join('\n')}
</urlset>
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
    },
  });
};
