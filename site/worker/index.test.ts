// Run from site/:
//
//   npx vitest run worker/index.test.ts
//
// vitest is not a dependency of site/package.json and must not become one — the
// site ships with astro alone and a clean `npm audit`. npx walks up to the
// repository root's node_modules and finds the vitest the rest of the repo
// already uses, which is why this file needs no config and no install.
//
// WHAT THIS SUITE IS FOR
//
// The Worker's three responsibilities are all invisible in a browser until they
// are wrong: a redirect that lost its counter still looks fine, a 404 without
// security headers still renders, and an allowlist that stopped being one still
// serves every link on the site correctly. Each test below pins one property
// that has no other observable symptom.
import { describe, expect, it, vi } from 'vitest';

import worker, { type Env } from './index';
import { BASE_HEADERS } from '../src/headers';
import { CHANNELS, GO_TARGETS, type Channel } from '../src/shared/links';

/** Every channel, including `github`, which is absent from CHANNELS by design. */
const ALL_CHANNELS = Object.keys(GO_TARGETS) as Channel[];

const ASSET_BODY = '<!doctype html><title>Not found</title>';

/**
 * An env with a working asset binding and no counter — the shape production
 * has today, since the GO_CLICKS binding in wrangler.jsonc is commented out.
 * Tests that care about counting build their own.
 */
function env(overrides: Partial<Env> = {}): Env {
  return {
    ASSETS: {
      fetch: async (request: Request) =>
        new URL(request.url).pathname === '/404.html'
          ? new Response(ASSET_BODY, { status: 200, headers: { 'Content-Type': 'text/html' } })
          : new Response('', { status: 404 }),
    },
    ...overrides,
  };
}

const get = (path: string, e: Env = env()) =>
  worker.fetch(new Request(`https://example.invalid${path}`), e);

const getFrom = (host: string, path: string, e: Env = env()) =>
  worker.fetch(new Request(`https://${host}${path}`), e);

// HSTS is decided from the request's hostname, and it has to be, because the
// obvious alternative is broken in a way tests cannot see. Reading
// `process.env` here works under vitest and is a ReferenceError in the Workers
// runtime, which has no `process` without `nodejs_compat`. The previous version
// caught that throw and fell back to no-HSTS — correct while the site had no
// domain, and permanently correct afterwards too: attaching a real domain would
// have turned HSTS on for the static pages and left every redirect and the 404
// without it, silently.
describe('HSTS is a property of the hostname, not of the build', () => {
  it('does not pin *.workers.dev, which is shared with every other Worker', async () => {
    for (const path of ['/go/vscode', '/nope']) {
      const res = await getFrom('vibeguard-site.workers.dev', path);
      expect(res.headers.get('Strict-Transport-Security')).toBeNull();
    }
  });

  it('does not pin localhost either', async () => {
    const res = await getFrom('localhost:8787', '/go/chrome');
    expect(res.headers.get('Strict-Transport-Security')).toBeNull();
  });

  it('pins a custom domain, on the redirects and on the 404 alike', async () => {
    for (const path of ['/go/vscode', '/nope']) {
      const res = await getFrom('vibeguard.example', path);
      expect(res.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains');
    }
  });

  it('never throws reaching for a Node global the Workers runtime lacks', async () => {
    // The regression this whole change is about: `process` is undefined in
    // production. Deleting it here makes the test environment match.
    const saved = globalThis.process;
    try {
      // @ts-expect-error — deliberately removing a global the runtime lacks.
      delete globalThis.process;
      const res = await getFrom('vibeguard.example', '/go/action');
      expect(res.status).toBe(302);
      expect(res.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains');
    } finally {
      globalThis.process = saved;
    }
  });
});

describe('/go/<channel>', () => {
  it('redirects each allowlisted channel to exactly the URL in links.ts', async () => {
    // Compared against the table rather than against literals: a literal here
    // would be the second copy of a store URL that links.ts exists to prevent,
    // and it would pass while the site pointed somewhere else.
    for (const channel of ALL_CHANNELS) {
      const response = await get(`/go/${channel}`);
      expect(response.status, channel).toBe(302);
      expect(response.headers.get('Location'), channel).toBe(GO_TARGETS[channel]);
    }
  });

  it('covers all five channels, including the one the install page omits', () => {
    // CHANNELS is the four installable ones; `github` is a repository link.
    // Both still need a redirect, so the loop above must not shrink to CHANNELS.
    expect(ALL_CHANNELS).toHaveLength(5);
    expect(ALL_CHANNELS).toEqual(expect.arrayContaining([...CHANNELS, 'github']));
  });

  it('is a 302 and not a 301', async () => {
    // A cached permanent redirect means the second click never reaches the
    // Worker and the click count silently under-reports. This is the assertion
    // that makes that decision survive a future "301 is more correct" edit.
    const response = await get('/go/vscode');
    expect(response.status).toBe(302);
    expect(response.status).not.toBe(301);
  });

  it('tolerates one trailing slash without minting a second counter key', async () => {
    const counter = { writeDataPoint: vi.fn() };
    const response = await get('/go/chrome/', env({ GO_CLICKS: counter }));
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe(GO_TARGETS.chrome);
    expect(counter.writeDataPoint.mock.calls[0][0].indexes[0]).toMatch(/^go:chrome:/);
  });
});

describe('the allowlist', () => {
  it('404s an unknown channel instead of redirecting', async () => {
    const response = await get('/go/evil');
    expect(response.status).toBe(404);
    expect(response.headers.get('Location')).toBeNull();
  });

  it('never redirects to an attacker-supplied destination', async () => {
    // The open-redirect shapes that a pattern-based /go/:rest would accept.
    for (const path of [
      '/go/https://evil.example',
      '/go/%2f%2fevil.example',
      '/go//evil.example',
      '/go/vscode/extra',
      '/go/VSCODE',
      '/go/',
      '/go',
    ]) {
      const response = await get(path);
      expect(response.headers.get('Location'), path).toBeNull();
      expect(response.status, path).toBe(404);
    }
  });

  it('answers an unknown /go/ path exactly like any other missing page', async () => {
    // No distinct "unknown channel" response, which would tell a prober which
    // segments exist.
    const [unknownChannel, unknownPage] = await Promise.all([get('/go/evil'), get('/nope')]);
    expect(unknownChannel.status).toBe(unknownPage.status);
    expect(await unknownChannel.text()).toBe(await unknownPage.text());
  });
});

describe('the 404 page', () => {
  it('serves the built 404 asset with a 404 status', async () => {
    const response = await get('/nope');
    expect(response.status).toBe(404);
    expect(await response.text()).toBe(ASSET_BODY);
  });

  it('still answers with the site headers when the asset binding is absent', async () => {
    // Without this fallback the platform's own error screen would be served,
    // and it carries none of the headers below.
    const response = await worker.fetch(new Request('https://example.invalid/nope'), {});
    expect(response.status).toBe(404);
    expect(response.headers.get('Content-Security-Policy')).toBe(
      BASE_HEADERS['Content-Security-Policy'],
    );
    expect(await response.text()).toContain('Not found');
  });
});

describe('security headers', () => {
  it('are on both response paths', async () => {
    // Both of these are generated by Worker code, which Cloudflare documents as
    // NOT covered by the _headers file. If this test ever passes for only one
    // of the two, half the site is unprotected in a way nothing else reports.
    for (const path of ['/go/vscode', '/nope']) {
      const response = await get(path);
      for (const [name, value] of Object.entries(BASE_HEADERS)) {
        expect(response.headers.get(name), `${path} ${name}`).toBe(value);
      }
    }
  });

  it('declare a CSP with no script execution and no external origins', async () => {
    const csp = (await get('/go/vscode')).headers.get('Content-Security-Policy') ?? '';
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("default-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('http');
  });

  it('put no-store and noindex on /go/* only', async () => {
    const redirect = await get('/go/action');
    expect(redirect.headers.get('Cache-Control')).toBe('no-store');
    expect(redirect.headers.get('X-Robots-Tag')).toBe('noindex');

    // The 404 must not carry them: no-store there would be a pointless
    // instruction, and the pair exists to protect the click count, which a 404
    // does not have.
    const missing = await get('/nope');
    expect(missing.headers.get('Cache-Control')).toBeNull();
    expect(missing.headers.get('X-Robots-Tag')).toBeNull();
  });
});

describe('click counting', () => {
  it('writes go:<channel>:<YYYY-MM-DD> in UTC, once', async () => {
    const counter = { writeDataPoint: vi.fn() };
    await get('/go/openvsx', env({ GO_CLICKS: counter }));

    expect(counter.writeDataPoint).toHaveBeenCalledTimes(1);
    const event = counter.writeDataPoint.mock.calls[0][0];
    const today = new Date().toISOString().slice(0, 10);
    expect(event.indexes).toEqual([`go:openvsx:${today}`]);
    expect(event.doubles).toEqual([1]);
  });

  it('records nothing beyond channel, day and the count', async () => {
    // The three fields /privacy commits to. A fourth one appearing here is a
    // /privacy edit, not a test edit.
    const counter = { writeDataPoint: vi.fn() };
    await get('/go/github', env({ GO_CLICKS: counter }));

    const event = counter.writeDataPoint.mock.calls[0][0];
    const today = new Date().toISOString().slice(0, 10);
    expect(Object.keys(event).sort()).toEqual(['blobs', 'doubles', 'indexes']);
    expect(event.blobs).toEqual(['github', today]);
  });

  it('redirects normally when the binding is missing', async () => {
    // The state production is actually in: GO_CLICKS is commented out in
    // wrangler.jsonc until Analytics Engine is confirmed available.
    const response = await get('/go/vscode', { ASSETS: env().ASSETS });
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe(GO_TARGETS.vscode);
  });

  it('redirects normally when the binding throws', async () => {
    const counter = {
      writeDataPoint: vi.fn(() => {
        throw new Error('dataset unavailable');
      }),
    };
    const response = await get('/go/vscode', env({ GO_CLICKS: counter }));
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe(GO_TARGETS.vscode);
    expect(counter.writeDataPoint).toHaveBeenCalled();
  });

  it('does not count a path that is not a redirect', async () => {
    const counter = { writeDataPoint: vi.fn() };
    await get('/go/evil', env({ GO_CLICKS: counter }));
    await get('/nope', env({ GO_CLICKS: counter }));
    expect(counter.writeDataPoint).not.toHaveBeenCalled();
  });
});

describe('what the Worker reads', () => {
  it('reads nothing from the request but the path', async () => {
    // Structural, not aspirational: the request is handed to the Worker with
    // every property that could identify a visitor replaced by a getter that
    // fails the test if it is touched. /privacy's claim is this test.
    const request = new Request('https://example.invalid/go/vscode', {
      headers: { 'User-Agent': 'probe', Referer: 'https://elsewhere.invalid/', Cookie: 'a=1' },
    });
    const forbidden = ['headers', 'body', 'cf', 'method', 'referrer'];
    for (const property of forbidden) {
      Object.defineProperty(request, property, {
        get() {
          throw new Error(`the Worker read request.${property}`);
        },
      });
    }

    const response = await worker.fetch(request, env());
    expect(response.status).toBe(302);
  });
});
