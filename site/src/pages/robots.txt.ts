// /robots.txt — generated, so that the Sitemap line can exist.
//
// This was a static file in public/, and static is why the site went live with
// no `Sitemap:` directive. That directive takes an ABSOLUTE URL, which is not
// knowable at the time a file is written by hand: the site had no domain, and
// then it had a *.workers.dev one, and it may have a real one later. A file
// that cannot express the value has to omit it forever, and omitting it means a
// crawler that reaches robots.txt is not told where the sitemap is — on a site
// whose entire index is six pages and whose only SEO asset is /rules.
//
// Generated, the line appears exactly when there is a true value for it and is
// absent otherwise. Same rule the rest of this site follows for numbers: emit
// what is known, never a placeholder.
//
// The allow/disallow content is unchanged from the static version.
import type { APIRoute } from 'astro';

/** The six indexable pages, matching sitemap.xml. */
const ALLOW = ['/', '/install', '/rules', '/research/compiler', '/news', '/privacy'] as const;

export const GET: APIRoute = ({ site }) => {
  const lines = [
    '# The site is six pages and five redirects. Only the six belong in an index.',
    '#',
    '# /go/* is disallowed rather than merely left out. Those paths count a click',
    '# and then send the visitor to an extension store; a crawler that follows them',
    '# inflates the count, and a redirect URL that reaches a search result lets a',
    '# visitor land on a store without ever passing the install page, which is what',
    '# the per-channel comparison is measured against. The Worker sends',
    '# `X-Robots-Tag: noindex` on the same responses, because a rule here is a',
    '# request and a header is an instruction on the response itself.',
    '',
    'User-agent: *',
    '',
    ...ALLOW.map((p) => `Allow: ${p}`),
    '',
    'Disallow: /go/',
    '',
  ];

  if (site) {
    lines.push(`Sitemap: ${new URL('/sitemap.xml', site).href}`, '');
  } else {
    lines.push(
      '# No Sitemap: line. The directive requires an absolute URL and this build',
      '# was made without SITE_ORIGIN set, so the site does not yet know its own',
      '# address. Naming a guessed one would point crawlers at nothing.',
      '',
    );
  }

  return new Response(lines.join('\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
