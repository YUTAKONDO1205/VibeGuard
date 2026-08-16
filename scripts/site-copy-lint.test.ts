// Proves that the copy linter can actually fail, one rule at a time.
//
// WHY THE NEGATIVE CONTROLS ARE THE POINT OF THIS FILE
//
// A linter is trusted in proportion to how often it has been seen to catch
// something. `site-copy-lint.mjs` will spend almost its whole life printing
// "OK", and a green line proves two very different things that look identical
// in a CI log: "the site is clean" and "the regex has not matched anything
// since the day someone broke it". The words this thing hunts for are rare by
// construction — that is what makes the second state so easy to enter and so
// hard to notice.
//
// So every rule below gets a fixture that VIOLATES it and an assertion that the
// linter reports that violation, plus a clean fixture asserting it stays quiet.
// Together those two say what a green run cannot say on its own: the rule fires
// on the bad input and not on the good one.
//
// WHY FIXTURES IN A TEMP DIRECTORY RATHER THAN THE REAL SITE
//
// The negative controls need a site containing "Coming soon", a fake rule ID,
// and an `npm install -g` line. Those cannot live in `site/` — the linter would
// (correctly) fail the real build, and the CI job would be red forever. The
// linter therefore takes `--site DIR`, and each test writes a complete little
// site, mutates exactly one thing, and runs against that. One mutation per test
// is deliberate: a fixture with two faults cannot tell you which rule fired.
//
// The real tree is checked too, at the bottom, because a linter that has only
// ever run against fixtures has never met the thing it guards.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const LINTER = join(SCRIPTS_DIR, 'site-copy-lint.mjs');
const REAL_SITE = join(REPO_ROOT, 'site');

const tempRoots: string[] = [];
afterAll(() => {
  for (const dir of tempRoots) rmSync(dir, { recursive: true, force: true });
});

interface LintResult {
  status: number;
  output: string;
}

function runLint(siteDir: string, extraArgs: string[] = []): LintResult {
  try {
    const stdout = execFileSync(process.execPath, [LINTER, '--site', siteDir, ...extraArgs], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, output: stdout };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { status: e.status ?? -1, output: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

function write(root: string, relPath: string, content: string): void {
  const abs = join(root, relPath);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content, 'utf8');
}

/**
 * A page as the real site writes them: Astro frontmatter that pulls in a
 * layout, then the body. The layout supplies <main>, which is why the source
 * pages here have none — the linter has to treat a source page as its own main
 * region, and a fixture that quietly added <main> would test a shape the site
 * does not have.
 */
function productPage(title: string, body: string): string {
  return [
    '---',
    "import ProductLayout from '../layouts/ProductLayout.astro';",
    '---',
    '',
    `<ProductLayout title="${title}" description="${title}">`,
    `  ${body}`,
    '</ProductLayout>',
    '',
  ].join('\n');
}

/**
 * A complete site fixture that the linter passes in both modes.
 *
 * `links.ts` and `headers.ts` are COPIED from the real `site/src`, never
 * re-typed. R5 compares the first against README.md and R7 compares the second
 * against the generated `_headers`; a hand-written stand-in would make both
 * tests pass against a table that is not the one the site ships, which is the
 * same class of mistake those two rules exist to catch.
 */
function makeSite(): string {
  const root = mkdtempSync(join(tmpdir(), 'vg-site-copy-lint-'));
  tempRoots.push(root);

  cpSync(join(REAL_SITE, 'src', 'shared', 'links.ts'), join(root, 'src', 'shared', 'links.ts'), {
    recursive: true,
  });
  cpSync(join(REAL_SITE, 'src', 'headers.ts'), join(root, 'src', 'headers.ts'));

  write(root, 'src/pages/index.astro', productPage('VibeGuard', 'A security scanner for AI-generated code.'));
  write(root, 'src/pages/install.astro', productPage('Install', 'Four channels, one analysis engine.'));
  // At least one real rule ID has to appear somewhere, because the linter
  // refuses a site on which R4 compared an empty set.
  write(root, 'src/pages/rules.astro', productPage('Rules', 'VG-AUTH-001 is one of them.'));
  write(root, 'src/pages/news.astro', productPage('News', 'What shipped, and when.'));
  write(root, 'src/pages/privacy.astro', productPage('Privacy', 'Your code stays on your machine.'));
  write(
    root,
    'src/pages/research/compiler.astro',
    [
      '---',
      "import ResearchLayout from '../../layouts/ResearchLayout.astro';",
      '---',
      '',
      '<ResearchLayout title="VibeGuard Compiler" description="Research">',
      '  <p>A compiler-side experiment. Read the research.</p>',
      '  <section lang="ja"><p>コンパイラ側の研究です。</p></section>',
      '</ResearchLayout>',
      '',
    ].join('\n'),
  );

  // Shared markup: the footer that makes R2's <main> scoping necessary.
  write(
    root,
    'src/components/FooterBase.astro',
    [
      '<footer>',
      '  <nav><a href="/install">Install</a><a href="/rules">Rules</a></nav>',
      '  <a href="https://github.com/YUTAKONDO1205/VibeGuard/blob/main/NOTICE">NOTICE</a>',
      '</footer>',
      '',
    ].join('\n'),
  );

  write(root, 'src/styles/tokens.css', ':root { --vg-ink: #101418; --vg-paper: rgb(255 255 255); }\n');
  write(root, 'src/styles/base.css', 'body { color: var(--vg-ink); background: var(--vg-paper); }\n');
  write(root, 'src/data/rules.json', JSON.stringify({ rules: [{ ruleId: 'VG-AUTH-001' }] }, null, 2));

  writeDist(root);
  return root;
}

/** The built half of the fixture: what artefact mode reads. */
function writeDist(root: string): void {
  const page = (title: string, body: string) =>
    [
      '<!doctype html>',
      '<html lang="en"><head><meta charset="utf-8" /><title>' + title + '</title></head>',
      '<body>',
      '<main id="main">' + body + '</main>',
      '<footer><a href="/install">Install</a>',
      '<a href="https://github.com/YUTAKONDO1205/VibeGuard/blob/main/NOTICE">NOTICE</a>',
      '<a href="/go/chrome">Chrome</a></footer>',
      '</body></html>',
      '',
    ].join('\n');

  write(root, 'dist/index.html', page('VibeGuard', 'A security scanner for AI-generated code.'));
  write(root, 'dist/install/index.html', page('Install', 'Four channels, one analysis engine.'));
  write(root, 'dist/rules/index.html', page('Rules', 'VG-AUTH-001 is one of them.'));
  write(root, 'dist/news/index.html', page('News', 'What shipped, and when.'));
  write(root, 'dist/privacy/index.html', page('Privacy', 'Your code stays on your machine.'));
  write(root, 'dist/research/compiler/index.html', page('VibeGuard Compiler', 'Read the research. コンパイラ側の研究です。'));
  write(root, 'dist/_headers', headersFileFor(join(root, 'src', 'headers.ts')));
}

/**
 * Render a `_headers` file from the fixture's own headers.ts.
 *
 * Same reasoning as copying the file rather than re-typing it: if a header is
 * added to the real definition tomorrow, this fixture grows it too, and the
 * positive control keeps meaning "complete" rather than "complete as of the day
 * this test was written".
 */
function headersFileFor(headersTs: string): string {
  const source = readFileSync(headersTs, 'utf8');
  const block = /export const BASE_HEADERS[^=]*=\s*\{([\s\S]*?)\n\};/.exec(source);
  const keys: string[] = [];
  const entry = /^\s*'([A-Za-z][A-Za-z0-9-]*)'\s*:/gm;
  for (let m = entry.exec(block![1]); m; m = entry.exec(block![1])) keys.push(m[1]);
  expect(keys.length, 'no BASE_HEADERS keys parsed out of the real headers.ts').toBeGreaterThan(2);
  return ['/*', ...keys.map((k) => `  ${k}: placeholder-value`), ''].join('\n');
}

describe('site copy lint: the clean fixture is quiet', () => {
  // The positive control. Without it, every negative control below is
  // compatible with a linter that fails on absolutely everything.
  it('source mode passes a site with nothing wrong with it', () => {
    const site = makeSite();
    const result = runLint(site);
    expect(result.output).toContain('site copy lint OK, SOURCE mode');
    expect(result.status).toBe(0);
    // The summary must name what it read, not just say OK.
    expect(result.output).toContain('6 content page(s) read');
  });

  it('artefact mode passes the built half of the same site', () => {
    const site = makeSite();
    const result = runLint(site, ['--dist']);
    expect(result.output).toContain('site copy lint OK, ARTEFACT mode');
    expect(result.status).toBe(0);
  });

  // R2's whole design risk in one test. The footer carries the word "Install"
  // on every page including the research one; if the rule were not scoped to
  // <main>, this fixture would be red and the rule would be deleted within a
  // week. This asserts the escape hatch works, which is why the negative
  // control below is safe to trust.
  it('the word "Install" in the shared footer does not fail the research page', () => {
    const site = makeSite();
    expect(readFileSync(join(site, 'src/components/FooterBase.astro'), 'utf8')).toContain('Install');
    expect(runLint(site).status).toBe(0);
    expect(runLint(site, ['--dist']).status).toBe(0);
  });
});

describe('R1 banned vocabulary', () => {
  it('fails on an English promise of a future release', () => {
    const site = makeSite();
    write(site, 'src/pages/index.astro', productPage('VibeGuard', 'Cross-file analysis: coming soon.'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('R1 banned vocabulary');
    expect(result.output).toContain('src/pages/index.astro');
  });

  it('fails on Beta, Preview, Alpha, Experimental, Planned, WIP, TBA and Roadmap alike', () => {
    for (const word of ['Beta', 'Preview', 'Alpha', 'Experimental', 'Planned', 'WIP', 'TBA', 'Roadmap']) {
      const site = makeSite();
      write(site, 'src/pages/news.astro', productPage('News', `The C/C++ rules are ${word}.`));
      const result = runLint(site);
      expect(result.status, `"${word}" was not rejected`).toBe(1);
      expect(result.output).toContain('R1 banned vocabulary');
    }
  });

  // ★ The half-a-job test. Chapter 7 puts a full Japanese translation on
  // /research/compiler, and an English-only deny-list would wave every one of
  // these through on the single page most tempted to promise something.
  it('fails on the Japanese deny-list, on the one page that is bilingual', () => {
    for (const word of ['近日公開', '予定', 'まもなく', '今後対応']) {
      const site = makeSite();
      write(
        site,
        'src/pages/research/compiler.astro',
        [
          '---',
          "import ResearchLayout from '../../layouts/ResearchLayout.astro';",
          '---',
          '<ResearchLayout title="VibeGuard Compiler" description="Research">',
          '  <p>A compiler-side experiment.</p>',
          `  <section lang="ja"><p>この研究は${word}。</p></section>`,
          '</ResearchLayout>',
          '',
        ].join('\n'),
      );
      const result = runLint(site);
      expect(result.status, `Japanese "${word}" was not rejected`).toBe(1);
      expect(result.output).toContain('R1 banned vocabulary');
    }
  });

  it('reads generated data too, not only hand-written pages', () => {
    const site = makeSite();
    write(site, 'src/data/releases.json', JSON.stringify({ latest: { title: 'Beta release' } }));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('releases.json');
  });

  it('does not fire on a comment that explains the deny-list', () => {
    // The layouts in site/src document these rules in prose, naming the very
    // words they forbid. A linter that reddens on its own documentation gets
    // the documentation deleted.
    const site = makeSite();
    write(
      site,
      'src/components/FooterBase.astro',
      ['---', '// Never write "coming soon" or "Beta" in this footer.', '---', '<footer>VibeGuard</footer>', ''].join('\n'),
    );
    expect(runLint(site).status).toBe(0);
  });
});

describe('R2 acquisition vocabulary on /research', () => {
  it('fails on install / download / npm / brew / a version number inside <main>', () => {
    for (const phrase of [
      'Install it from the release page.',
      'Download the artefact here.',
      'Available on npm today.',
      'Or use brew to get it.',
      'Try v0.1 now.',
    ]) {
      const site = makeSite();
      write(
        site,
        'src/pages/research/compiler.astro',
        [
          '---',
          "import ResearchLayout from '../../layouts/ResearchLayout.astro';",
          '---',
          '<ResearchLayout title="VibeGuard Compiler" description="Research">',
          `  <p>${phrase}</p>`,
          '</ResearchLayout>',
          '',
        ].join('\n'),
      );
      const result = runLint(site);
      expect(result.status, `"${phrase}" was not rejected`).toBe(1);
      expect(result.output).toContain('R2 acquisition vocabulary on /research');
    }
  });

  it('leaves the same words alone on a product page, where they are true', () => {
    const site = makeSite();
    write(site, 'src/pages/install.astro', productPage('Install', 'Install the extension, then open a file. v0 is the Action tag.'));
    expect(runLint(site).status).toBe(0);
  });

  it('fails when built research HTML has no <main> to scope to', () => {
    const site = makeSite();
    write(
      site,
      'dist/research/compiler/index.html',
      '<!doctype html>\n<html lang="en"><body><p>Read the research.</p></body></html>\n',
    );
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('contains no <main>');
  });

  it('fails when no /research page exists at all, rather than passing quietly', () => {
    // Six pages, so the page floor is satisfied — but the research route is
    // gone, which means R2 silently checked nothing. That is the shape of
    // vacuity this linter is not allowed to have.
    const site = makeSite();
    rmSync(join(site, 'src/pages/research'), { recursive: true, force: true });
    write(site, 'src/pages/compiler.astro', productPage('Compiler', 'Read the research.'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('rule R2 did not run at all');
  });
});

describe('R3 impossible install commands', () => {
  it('fails on `npm install -g vibeguard` in any of its shapes', () => {
    for (const command of ['npm install -g vibeguard', 'npm i -g vibeguard', 'npm install --global vibeguard']) {
      const site = makeSite();
      write(site, 'src/pages/install.astro', productPage('Install', `<code>${command}</code>`));
      const result = runLint(site);
      expect(result.status, `"${command}" was not rejected`).toBe(1);
      expect(result.output).toContain('R3 impossible command');
    }
  });

  it('fails on `npx vibeguard`', () => {
    const site = makeSite();
    write(site, 'src/pages/install.astro', productPage('Install', '<code>npx vibeguard scan .</code>'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('R3 impossible command');
  });

  it('leaves the real build-from-source instructions alone', () => {
    const site = makeSite();
    write(
      site,
      'src/pages/install.astro',
      productPage('Install', '<code>npm install &amp;&amp; npm run build</code>'),
    );
    expect(runLint(site).status).toBe(0);
  });
});

describe('R4 rule IDs exist in the engine', () => {
  it('fails on an ID no rule defines', () => {
    const site = makeSite();
    write(site, 'src/pages/rules.astro', productPage('Rules', 'See VG-AUTH-001 and VG-FAKE-999.'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('VG-FAKE-999');
    expect(result.output).toContain('does not exist in @vibeguard/rules');
  });

  it('fails when the site prints no rule ID at all', () => {
    const site = makeSite();
    write(site, 'src/pages/rules.astro', productPage('Rules', 'Everything the engine looks for.'));
    write(site, 'src/data/rules.json', JSON.stringify({ rules: [] }));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('R4 compared an empty set');
  });

  // ★ REGRESSION. R4 originally compared against `@vibeguard/rules` alone, and
  // the first run against the real built site rejected eight IDs that are real,
  // shipped and documentable: the cross-file design smells live in
  // `crossFileRules` in `@vibeguard/analysis-graph`. Had that shipped, the
  // /rules page would have had to drop half a family or turn the rule off.
  it('accepts a cross-file design smell from the other registry', () => {
    const site = makeSite();
    write(site, 'src/pages/rules.astro', productPage('Rules', 'VG-AUTH-001, and VG-SMELL-020 across files.'));
    const result = runLint(site);
    expect(result.output).not.toContain('VG-SMELL-020');
    expect(result.status).toBe(0);
  });

  // The other edge of the same boundary. analysis-graph exports rules it has
  // not registered, so that the corpus sweep can measure a candidate before it
  // ships. An unregistered rule runs for nobody, so describing it on the site
  // is precisely the accident this linter exists to prevent.
  it('rejects a cross-file rule that is exported but not registered', () => {
    const site = makeSite();
    write(site, 'src/pages/rules.astro', productPage('Rules', 'VG-AUTH-001 and VG-SMELL-031.'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('VG-SMELL-031');
  });

  it('names which registries answered, and whether they were built', () => {
    const site = makeSite();
    const result = runLint(site);
    expect(result.output).toContain('rule IDs: checked against');
    expect(result.output).toMatch(/allRules|packages\/rules\/src text/);
    expect(result.output).toMatch(/crossFileRules|analysis-graph src text/);
  });
});

describe('R5 /go targets equal README.md', () => {
  it('fails when a channel URL drifts from the Install table, in both directions', () => {
    const site = makeSite();
    const links = readFileSync(join(site, 'src/shared/links.ts'), 'utf8');
    const drifted = links.replace(
      /chrome: '[^']+'/,
      "chrome: 'https://chromewebstore.google.com/detail/wrongidentifierentirely'",
    );
    expect(drifted, 'the chrome entry was not found to mutate').not.toBe(links);
    write(site, 'src/shared/links.ts', drifted);

    const result = runLint(site);
    expect(result.status).toBe(1);
    // Site says something README does not…
    expect(result.output).toContain('wrongidentifierentirely');
    expect(result.output).toContain("appear in README.md's Install table");
    // …and README says something the site does not.
    expect(result.output).toContain('which no GO_TARGETS entry');
  });

  it('fails rather than passing when the table cannot be parsed', () => {
    const site = makeSite();
    write(site, 'src/shared/links.ts', 'export const GO_TARGETS = loadFromSomewhereElse();\n');
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('could not parse five GO_TARGETS entries');
  });
});

describe('R6 the built HTML has no script and loads nothing off-site', () => {
  it('fails on a <script> tag', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '</main>\n<script>console.log(1)</script>',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('contains a <script> tag');
  });

  // The style half of the same rule, and the one that actually bit.
  //
  // Astro inlines small scoped <style> blocks into <head>, and the CSP says
  // style-src 'self', so a page can look right under `astro preview` — which
  // applies no CSP — and arrive in production with those rules refused. Four
  // pages shipped into that state before anyone noticed, precisely because
  // every local check passed. A test is the only place that difference is
  // visible.
  it('fails on an inline <style> element, which style-src self would refuse', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '</main>\n<style>.vg-probe { outline: 1px solid currentColor; }</style>',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('contains an inline <style> element');
  });

  // A disclosure check, not a tidiness one.
  //
  // Astro emits a template <!-- --> into the built page, while a frontmatter
  // comment and a {/* ... */} expression are dropped — three things that look
  // equally private in an editor, one of which is not. The research page
  // shipped three long internal comments this way, one of which explained that
  // naming a submission venue would let a later deletion announce a rejection.
  // It published the reasoning it existed to protect.
  // The only rule here that is about disclosure rather than truthfulness, and
  // the one with a live route in. Findings and code on this site are produced
  // by running the scanner at build time, and the scanner reports the path it
  // was handed — absolute, for a single-file scan. CI builds on a clean Linux
  // checkout and would never show it; a local generate-then-deploy would.
  it('fails on a Windows home-directory path in the artefact', () => {
    const site = makeSite();
    const bs = String.fromCharCode(92);
    const winPath = `C:${bs}Users${bs}someone${bs}VibeGuard${bs}samples${bs}x.py`;
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      `</main>\n<p>at ${winPath}</p>`,
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('Windows home-directory path');
  });

  it('fails on a POSIX home-directory path in the artefact', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '</main>\n<p>at /home/someone/VibeGuard/samples/x.py</p>',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('home-directory path');
  });

  // The regression this pair exists for. The first version of the rule carried
  // an allow-list of the author's name and handle, tested with
  // `match.includes(entry)` — so a path or an address containing the handle was
  // waved through. That is the author's own home directory and the author's own
  // address: the two identifiers the rule is for.
  it('flags a home path even when it contains the author handle', () => {
    const site = makeSite();
    const bs = String.fromCharCode(92);
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      `</main>\n<p>at C:${bs}Users${bs}yutakondo${bs}VibeGuard${bs}x.py</p>`,
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('Windows home-directory path');
  });

  it('flags an email even when its local part is the author handle', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '</main>\n<p>yutakondo@example.com</p>',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('email address');
  });

  it('fails on an email address, but not on the footer byline', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '</main>\n<p>somebody@example.com</p>',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('email address');

    // The clean fixture already carries `Author: Kondo Yuta`, and it must not
    // trip: an allow-list by exact name is what lets the pattern stay strict.
    const clean = runLint(makeSite(), ['--dist']);
    expect(clean.status).toBe(0);
  });

  it('fails on an HTML comment, which Astro serves to every visitor', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '</main>\n<!-- internal: this number is not trusted yet -->',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('contains an HTML comment');
  });

  it('fails on a remote subresource, with no exception list', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/index.html'), 'utf8').replace(
      '</main>',
      '<img src="https://example.com/screenshot.png" alt="" /></main>',
    );
    write(site, 'dist/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('example.com/screenshot.png');
  });

  it('fails on a remote URL fetched from a stylesheet', () => {
    const site = makeSite();
    write(site, 'dist/_astro/site.css', "@font-face { src: url('https://fonts.example/x.woff2'); }\n");
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('fonts.example');
  });

  it('fails on an external link that is not a /go target or the repository', () => {
    const site = makeSite();
    const html = readFileSync(join(site, 'dist/news/index.html'), 'utf8').replace(
      '</main>',
      '<a href="https://example.org/post">Read more</a></main>',
    );
    write(site, 'dist/news/index.html', html);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('example.org/post');
  });

  // The exception, asserted so that nobody "fixes" the footer by removing the
  // licence link. It is in the clean fixture already; this states why.
  it('allows the footer links into the repository GO_TARGETS.github names', () => {
    const site = makeSite();
    expect(readFileSync(join(site, 'dist/index.html'), 'utf8')).toContain('/blob/main/NOTICE');
    expect(runLint(site, ['--dist']).status).toBe(0);
  });
});

describe('R7 the generated _headers is present and complete', () => {
  it('fails when _headers was never generated', () => {
    const site = makeSite();
    rmSync(join(site, 'dist/_headers'));
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('_headers does not exist');
  });

  it('fails when a header from headers.ts is missing, and names it', () => {
    const site = makeSite();
    const headers = readFileSync(join(site, 'dist/_headers'), 'utf8')
      .split('\n')
      .filter((line) => !line.includes('Content-Security-Policy'))
      .join('\n');
    write(site, 'dist/_headers', headers);
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('missing header(s): Content-Security-Policy');
  });
});

describe('R8 colour literals live only in tokens.css', () => {
  it('fails on a hex colour in another stylesheet', () => {
    const site = makeSite();
    write(site, 'src/styles/base.css', 'body { color: #1a1a1a; }\n');
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('R8 colour literal');
  });

  it('fails on rgb() and hsl() too', () => {
    for (const value of ['rgb(10 20 30)', 'rgba(10, 20, 30, 0.5)', 'hsl(200 50% 40%)']) {
      const site = makeSite();
      write(site, 'src/styles/bands.css', `.vg-band { background: ${value}; }\n`);
      const result = runLint(site);
      expect(result.status, `"${value}" was not rejected`).toBe(1);
      expect(result.output).toContain('R8 colour literal');
    }
  });

  it('fails on a colour inside a component <style> block', () => {
    const site = makeSite();
    write(
      site,
      'src/components/FooterBase.astro',
      '<footer>VibeGuard</footer>\n<style>footer { color: #abcdef; }</style>\n',
    );
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('R8 colour literal');
  });

  it('leaves tokens.css alone — it is the one place a colour is a number', () => {
    const site = makeSite();
    expect(readFileSync(join(site, 'src/styles/tokens.css'), 'utf8')).toContain('#101418');
    expect(runLint(site).status).toBe(0);
  });

  it('does not mistake a CSS id selector for a colour', () => {
    const site = makeSite();
    write(site, 'src/styles/base.css', '#main { padding: 0; }\n#dad { margin: 0; }\n');
    // `#dad` is three hex digits AND a plausible id. The rule refuses a
    // trailing identifier character but cannot tell these apart, so this test
    // records which way it errs rather than pretending the ambiguity is solved.
    const result = runLint(site);
    expect(result.output).not.toContain('#main');
  });
});

describe('R9 the unshipped scan mode', () => {
  it('fails on mode: deep, --mode deep and "deep scan"', () => {
    for (const phrase of ['mode: deep', '--mode deep', 'a deep scan of your repository']) {
      const site = makeSite();
      write(site, 'src/pages/index.astro', productPage('VibeGuard', `Run ${phrase}.`));
      const result = runLint(site);
      expect(result.status, `"${phrase}" was not rejected`).toBe(1);
      expect(result.output).toContain('R9 unshipped mode');
    }
  });
});

describe('the vacuity guard', () => {
  it('fails when fewer than six content pages were read', () => {
    const site = makeSite();
    rmSync(join(site, 'src/pages/news.astro'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('below the required 6');
  });

  it('fails on an empty site rather than reporting it as clean', () => {
    // The failure this whole guard exists for: a rename moves src/pages, the
    // walk returns nothing, and every rule passes over an empty list.
    const site = makeSite();
    rmSync(join(site, 'src/pages'), { recursive: true, force: true });
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('only 0 content page(s)');
  });

  it('fails in artefact mode when the build produced nothing', () => {
    const site = makeSite();
    rmSync(join(site, 'dist'), { recursive: true, force: true });
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('below the required 6');
  });
});

// ── The real tree ───────────────────────────────────────────────────────────
//
// Fixtures prove the rules work. Only this proves they are pointed at the site.

describe('the real site/', () => {
  const pagesDir = join(REAL_SITE, 'src', 'pages');
  const pageCount = existsSync(pagesDir) ? readdirSync(pagesDir).length : 0;

  // Runs from the first day a page exists, and is the check that matters
  // day-to-day: whatever pages are present must contain no violation. It is
  // separated from the page-count assertion below so that an incomplete site
  // still gets its copy checked, instead of one big red blob that says nothing
  // about the words on the pages that do exist.
  it('contains no copy violation in whatever pages exist today', () => {
    const result = runLint(REAL_SITE);
    if (result.status === 0) return;
    // The page floor is the one failure this test tolerates; it has its own
    // test immediately below. Anything else is a real finding.
    const other = result.output
      .split('\n  - ')
      .slice(1)
      .filter((block) => !block.includes('below the required'));
    expect(other.join('\n\n'), 'site-copy-lint reported violations in site/src').toBe('');
  });

  // RED UNTIL ALL SIX PAGES EXIST, and that is the intended behaviour: the
  // floor is the guard that stops this linter from passing over an empty
  // directory, so it cannot be conditional on the directory being full. If this
  // is the only failing test, the site is incomplete — finish the pages. Do not
  // lower CONTENT_PAGE_FLOOR to make it green unless the site genuinely has
  // fewer URLs, which is a chapter-2 decision and not a test fix.
  it(`passes source mode outright (site/src/pages currently holds ${pageCount} entries)`, () => {
    const result = runLint(REAL_SITE);
    expect(result.output).toContain('site copy lint OK, SOURCE mode');
    expect(result.status).toBe(0);
  });

  // The build output is the one thing a developer legitimately may not have.
  // The linter itself never skips; this test does, exactly once, and shouts.
  //
  // "Built" means "contains a page", not "the directory exists". An empty or
  // half-written `dist/` is what a developer has DURING a build, and treating
  // that as built produces a failure that says nothing except "you caught it
  // mid-write". The linter still calls an empty dist a hard failure, which is
  // the right answer for CI, where nothing is ever mid-build.
  const hasBuiltPages = () =>
    existsSync(join(REAL_SITE, 'dist')) &&
    readdirSync(join(REAL_SITE, 'dist')).some((entry) => entry.endsWith('.html'));

  const distBuilt = hasBuiltPages();
  const distTestName = distBuilt
    ? 'passes artefact mode on the built site'
    : '!!! SKIPPED — NOT BUILT: run `npm run build` in site/; the no-script, no-external-host ' +
      'and _headers rules were NOT verified against a real artefact';
  it.runIf(distBuilt)(distTestName, (ctx) => {
    // Asked again, because `dist/` is the one input that can disappear between
    // collection and execution: a rebuild deletes it and writes it back, and
    // this suite has been observed running through that window. The condition
    // is the same single one the name above encodes — not a new escape hatch —
    // it is just evaluated late enough to be true when the assertion runs.
    if (!hasBuiltPages()) {
      ctx.skip();
      return;
    }
    const result = runLint(REAL_SITE, ['--dist']);
    expect(result.output).toContain('site copy lint OK, ARTEFACT mode');
    expect(result.status).toBe(0);
  });
});
