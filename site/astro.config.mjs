// @ts-check
import { defineConfig } from 'astro/config';

// The domain is not registered yet, and this file must not assert one.
// `site` feeds canonical URLs and the absolute URLs in sitemap.xml, so a
// guessed value would publish a guess. Until a domain exists, the deploy runs
// on a *.workers.dev subdomain and SITE_ORIGIN carries whatever that is; with
// nothing set, `site` stays undefined and Astro emits relative URLs, which is
// the honest output for a site that does not yet know where it lives.
const origin = process.env.SITE_ORIGIN?.trim() || undefined;

export default defineConfig({
  // Astro's default. Named explicitly because the whole architecture rests on
  // it: static output ships no client runtime, which is what lets the CSP say
  // `script-src 'none'` without fighting the framework.
  output: 'static',

  site: origin,

  // Default. Left alone on purpose: Cloudflare's `assets.directory` in
  // wrangler.jsonc points at ./dist, and .gitignore's `dist/` line already
  // keeps the build output untracked. Three things line up here by default;
  // changing outDir breaks all three at once.
  outDir: './dist',

  build: {
    // 'directory' (the default) writes install/index.html, which makes
    // /install/ the canonical URL. The URL rule is no trailing slash, so
    // pages are emitted as install.html instead.
    format: 'file',

    // NOT the default, and it closes a trap rather than tuning anything.
    //
    // Astro's default is 'auto', which inlines a stylesheet chunk under about
    // 4KB into a <style> element in <head>. The CSP this site serves says
    // `style-src 'self'`, so such a block is refused by the browser and the
    // page renders without those rules — while `astro preview`, which applies
    // no CSP, shows it looking correct. Four pages had already shipped in that
    // state once; scripts/site-copy-lint.mjs --dist now fails the build on an
    // inline <style>, which catches it, but catching it at the end of a build
    // is worse than not being able to cause it.
    //
    // Today the site emits one chunk well over the threshold, so 'auto' would
    // not inline anything. That is exactly why this is worth writing down: the
    // day someone adds a second, smaller stylesheet, the default would start
    // inlining with no other change to point at.
    inlineStylesheets: 'never',
  },

  // The other half of the same rule. Astro will not silently accept the
  // trailing-slash variant; Cloudflare's assets.html_handling
  // "drop-trailing-slash" issues the 307 that gets a visitor back to the
  // canonical form.
  trailingSlash: 'never',

  // No client-side JavaScript is emitted by any page in this site. If a future
  // page ever needs it, that is a decision that has to be argued against the
  // privacy claims on /privacy — not something a bundler default should grant.
  devToolbar: { enabled: false },
});
