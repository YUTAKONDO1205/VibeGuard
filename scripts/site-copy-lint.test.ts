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
import { pickReleaseTag, releasedRuleIds } from './site-release-tag.mjs';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const LINTER = join(SCRIPTS_DIR, 'site-copy-lint.mjs');
const REAL_SITE = join(REPO_ROOT, 'site');

const tempRoots: string[] = [];
afterAll(() => {
  for (const dir of tempRoots) rmSync(dir, { recursive: true, force: true });
});

/**
 * The release the fixtures pretend to be, and the rules it pretends shipped.
 *
 * ★ WHY THE FIXTURES INJECT THIS RATHER THAN LETTING R4 READ REAL TAGS.
 *
 * R4 asks two questions — does this ID exist, and has it shipped — and the
 * second one is answered by `git tag`. A fixture that let it resolve real tags
 * would be testing the tag list of whatever clone happened to run it: green on
 * a full clone, red on the `--no-tags` fetch CI uses, and the failure would be
 * in the fixture's environment rather than in anything the fixture wrote. So
 * every fixture states its own released set, which is also the positive control
 * for the injection point itself — if `--released-ids` stopped being read, the
 * ID the clean fixture prints would stop being accepted and this whole file
 * would go red at once.
 *
 * `VG-AUTH-001` and `VG-SMELL-020` are the two the fixtures need: one from each
 * registry, both genuinely in the newest release. The tag resolution itself is
 * tested against the real repository at the bottom of this file, and the
 * fail-closed branch is tested by taking the git repository away.
 */
const FIXTURE_RELEASE_TAG = 'v0.0.0-fixture';
const FIXTURE_RELEASED_IDS = ['VG-AUTH-001', 'VG-SMELL-020'];

/**
 * An ID this repository writes down and no rule declares.
 *
 * `VG-SMELL-031` is a cross-file candidate that was DROPPED rather than
 * implemented; the only trace of it is prose in
 * `design-smells-crossfile/refused-security-inheritance.ts`. Both halves of
 * that sentence are asserted where the constant is used, because the comment
 * this replaced claimed the opposite and nobody had checked.
 */
const PROSE_ONLY_RULE_ID = 'VG-SMELL-031';

/**
 * ★ WHY THE TAG PROBE IS TWO FUNCTIONS AND NOT A try/catch (Defect 4).
 *
 * The real-repository test below can only run where `git tag --list` answers.
 * It used to decide that with `try { … } catch { return '' }` and a single skip
 * reason reading "NO RELEASE TAG IN THIS CHECKOUT: fetch tags". An empty string
 * is what git returns when a checkout genuinely has no tags AND what the catch
 * returns when git is not installed, when the directory is not a repository,
 * and when the call is refused — four causes, one message, three of them
 * misattributed. The reader is then sent to deepen a fetch that was never the
 * problem, and the thing the message is really reporting (that this assertion
 * did not run) is filed under the wrong cause.
 *
 * So the probe REPORTS which of the two it saw, the naming is a pure function
 * of that, and the naming is unit-tested below. A skip that lies about why it
 * skipped is a silent pass wearing a warning label.
 */
type TagProbe = { ok: true; tagList: string } | { ok: false; failure: string };

function probeReleaseTags(cwd: string): TagProbe {
  try {
    return {
      ok: true,
      tagList: execFileSync('git', ['tag', '--list', 'v*'], {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    };
  } catch (error) {
    const e = error as { message?: string; stderr?: string };
    const detail = String(e.stderr ?? '').trim() || e.message || String(error);
    return { ok: false, failure: detail.split('\n')[0].trim().slice(0, 200) };
  }
}

export function releaseTagAvailability(probe: TagProbe): {
  hasReleaseTag: boolean;
  testName: string;
} {
  if (!probe.ok) {
    return {
      hasReleaseTag: false,
      testName:
        '!!! SKIPPED — GIT DID NOT ANSWER: `git tag --list` failed (' +
        probe.failure +
        '). This is NOT the same as a checkout without tags: the list was never read, so the ' +
        'cause is git missing from PATH, a directory that is not a repository, or a refused ' +
        'call — and none of those is fixed by deepening a fetch. The released-set resolution ' +
        'was NOT verified against the real repository',
    };
  }
  const tags = probe.tagList
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  if (!tags.some((tag) => /^v\d+\.\d+\.\d+$/.test(tag))) {
    return {
      hasReleaseTag: false,
      testName:
        `!!! SKIPPED — GIT ANSWERED WITH NO RELEASE TAG: it listed ${tags.length} tag(s), none ` +
        'of the form vMAJOR.MINOR.PATCH. This is the shallow or --no-tags fetch: fetch tags ' +
        '(actions/checkout with fetch-depth: 0 and without --no-tags). The released-set ' +
        'resolution was NOT verified against the real repository',
    };
  }
  return {
    hasReleaseTag: true,
    testName: 'reads a set out of the real repository that is a subset of the working tree',
  };
}

const tagProbe = probeReleaseTags(REPO_ROOT);
const { hasReleaseTag, testName: realRepoTest } = releaseTagAvailability(tagProbe);

interface LintResult {
  status: number;
  output: string;
}

function runLint(siteDir: string, extraArgs: string[] = []): LintResult {
  // A caller that names its own release source means it: the fail-closed test
  // points --tag-repo at a directory with no repository in it, and handing that
  // run an injected set as well would answer the question it exists to refuse.
  const overridden = extraArgs.includes('--released-ids') || extraArgs.includes('--tag-repo');
  const idsFile = join(siteDir, 'released-ids.json');
  const injected =
    overridden || !existsSync(idsFile)
      ? []
      : ['--released-ids', idsFile, '--release-tag', FIXTURE_RELEASE_TAG];
  try {
    const stdout = execFileSync(
      process.execPath,
      [LINTER, '--site', siteDir, ...injected, ...extraArgs],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
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
  // The generated data in the shape site-export-rules.mjs writes it: the
  // release it filtered by, and the rules of that release. The tag is part of
  // the fixture rather than decoration — R4 refuses data that declares none,
  // because a file without one did not come from the generator and leaves the
  // stale-data cross-check silently unperformed.
  write(
    root,
    'src/data/rules.json',
    JSON.stringify({ releaseTag: FIXTURE_RELEASE_TAG, rules: [{ ruleId: 'VG-AUTH-001' }] }, null, 2),
  );

  // Not part of the site. `runLint` passes it to --released-ids, and it sits
  // outside src/ and public/ so that no rule reads it as content.
  write(root, 'released-ids.json', JSON.stringify(FIXTURE_RELEASED_IDS, null, 2));

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
    write(site, 'src/data/rules.json', JSON.stringify({ releaseTag: FIXTURE_RELEASE_TAG, rules: [] }));
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

  // ★ THIS TEST'S RATIONALE WAS FALSE, AND THE FIX IS THE RATIONALE.
  //
  // It used to be called "rejects a cross-file rule that is exported but not
  // registered", and its comment said the tag's source text DOES contain
  // unregistered candidates. Both halves are wrong, and neither was ever
  // measured. `VG-SMELL-031` has no `ruleId:` declaration in the working tree
  // or at v0.3.6; it survives only in two prose comments in
  // `design-smells-crossfile/refused-security-inheritance.ts` recording that
  // the candidate was DROPPED rather than implemented. So it is not exported,
  // it is not in any registry, and the tag's parse has never yielded it.
  //
  // What the fixture actually demonstrates is narrower and still worth having:
  // an ID that exists in this repository's own prose — which is exactly where
  // somebody writing copy would find one — is rejected unless a rule declares
  // it. The premise is pinned below rather than asserted in a comment, because
  // a sentence about the state of another package is the kind of claim that
  // rots silently, and this file already shipped one.
  it('rejects a rule ID that the repository only ever mentions in prose', () => {
    const crossFileDir = join(REPO_ROOT, 'packages', 'analysis-graph', 'src', 'design-smells-crossfile');
    const files = walkTs(crossFileDir);
    expect(files.length, 'the cross-file rule directory moved').toBeGreaterThan(0);

    const declared = new Set<string>();
    const mentionedInProse: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      const re = /ruleId: '(VG-[A-Z]+-\d+)'/g;
      for (let m = re.exec(text); m; m = re.exec(text)) declared.add(m[1]);
      if (text.includes(PROSE_ONLY_RULE_ID)) mentionedInProse.push(file);
    }
    // Both halves of the premise, so that the test name stays true. If the
    // candidate is ever implemented the first goes red; if the comments that
    // record its rejection are deleted the second does, and either way the
    // next person rewrites this rationale instead of inheriting it.
    expect(
      [...declared],
      `${PROSE_ONLY_RULE_ID} now has a ruleId declaration; this fixture needs a different ID`,
    ).not.toContain(PROSE_ONLY_RULE_ID);
    expect(
      mentionedInProse.length,
      `${PROSE_ONLY_RULE_ID} is no longer mentioned anywhere in ${crossFileDir}`,
    ).toBeGreaterThan(0);

    const site = makeSite();
    write(
      site,
      'src/pages/rules.astro',
      productPage('Rules', `VG-AUTH-001 and ${PROSE_ONLY_RULE_ID}.`),
    );
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain(PROSE_ONLY_RULE_ID);
    // It must fail as an ID nothing defines. Reported as "not in the release"
    // it would tell a reader to wait for a version that will never carry it.
    expect(result.output).toContain('does not exist in @vibeguard/rules');
    expect(result.output).not.toContain('exists in this checkout but is NOT in');
  });

  it('names which registries answered, and whether they were built', () => {
    const site = makeSite();
    const result = runLint(site);
    expect(result.output).toContain('rule IDs: checked against');
    expect(result.output).toMatch(/allRules|packages\/rules\/src text/);
    expect(result.output).toMatch(/crossFileRules|analysis-graph src text/);
  });
});

// ── The release gate: R4's second question ──────────────────────────────────
//
// `/rules` listed 89 rule IDs under a footer reading `Latest: v0.3.6`, which
// ships 85. The four extra were real — registered, tested, running on main —
// and in no artefact a visitor could install. R4 passed the page, because until
// now "exists" was the only question it asked, and the four exist.
//
// The tests below are the ones that would have caught it. The first is the one
// that did not exist before: an ID that IS in the checkout and is NOT in the
// release. The old fixture only ever used `VG-FAKE-999`, an ID that exists
// nowhere, which a checkout-scoped rule rejects just as happily — so the suite
// was green in a way that said nothing about the failure that actually shipped.
describe('R4 release gate: a rule has to have shipped, not merely to exist', () => {
  it('fails on a rule that exists in this checkout but is not in the release', () => {
    const site = makeSite();
    // Registered in `@vibeguard/rules` on this branch, absent from v0.3.6, and
    // one of the four that reached the public site early.
    write(site, 'src/pages/rules.astro', productPage('Rules', 'VG-AUTH-001 and VG-AUTH-009.'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('VG-AUTH-009');
    expect(result.output).toContain('exists in this checkout but is NOT in');
    // It must fail for the RIGHT reason. Reported as an unknown ID it would be
    // a lie of a different kind — the rule is real, and a reader sent to check
    // whether it exists will find that it does.
    expect(result.output).not.toContain('VG-AUTH-009, which does not exist');
  });

  it('accepts the same page when the ID is in the released set', () => {
    // The positive control for the test above: the difference between the two
    // runs is membership of the released set and nothing else.
    const site = makeSite();
    write(site, 'released-ids.json', JSON.stringify([...FIXTURE_RELEASED_IDS, 'VG-AUTH-009']));
    write(site, 'src/pages/rules.astro', productPage('Rules', 'VG-AUTH-001 and VG-AUTH-009.'));
    const result = runLint(site);
    expect(result.output).not.toContain('VG-AUTH-009');
    expect(result.status).toBe(0);
  });

  it('fails when the generated data names a different release than the run resolved', () => {
    const site = makeSite();
    write(
      site,
      'src/data/rules.json',
      JSON.stringify({ releaseTag: 'v0.0.1-stale', rules: [{ ruleId: 'VG-AUTH-001' }] }, null, 2),
    );
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('was generated as of v0.0.1-stale');
    expect(result.output).toContain('The generated data is stale');
  });

  it('says so in the summary when the generated data agrees', () => {
    const site = makeSite();
    write(
      site,
      'src/data/rules.json',
      JSON.stringify(
        { releaseTag: FIXTURE_RELEASE_TAG, rules: [{ ruleId: 'VG-AUTH-001' }] },
        null,
        2,
      ),
    );
    const result = runLint(site);
    expect(result.status).toBe(0);
    expect(result.output).toContain(`generated rules.json agrees it is ${FIXTURE_RELEASE_TAG}`);
  });

  // ★ THIS USED TO ASSERT THE SILENT PASS. The test was called 'distinguishes
  // "the tags agree" from "there was no tag to compare"', and it pinned the
  // behaviour that generated data with no releaseTag produces the note
  // "(tag NOT cross-checked)" on a run that exits 0 — a check that had stopped
  // happening, described accurately, in the summary of a green build. The
  // distinction it drew was real; the exit code was the defect.
  it('refuses generated data that declares no releaseTag, rather than noting it and passing', () => {
    const site = makeSite();
    write(
      site,
      'src/data/rules.json',
      JSON.stringify({ rules: [{ ruleId: 'VG-AUTH-001' }] }, null, 2),
    );
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('declares no releaseTag');
    expect(result.output).not.toContain('site copy lint OK');
  });

  it('distinguishes "the tags agree" from "there was nothing to compare it to"', () => {
    // `--released-ids` without `--release-tag` is a caller answering the first
    // question and declining the second: it says which rules shipped without
    // naming a release. The data's own tag then has nothing to be compared
    // against, and the summary must not let that read like agreement.
    const site = makeSite();
    const result = runLint(site, ['--released-ids', join(site, 'released-ids.json')]);
    expect(result.status).toBe(0);
    expect(result.output).toContain(`says ${FIXTURE_RELEASE_TAG} (nothing to compare it to)`);
    expect(result.output).not.toContain('agrees it is');
  });

  it('exits non-zero naming the reason when no release can be resolved, and does not skip', () => {
    const site = makeSite();
    // A directory with no repository in it: the same position a `--no-tags` or
    // shallow CI checkout is in, reachable without writing tags into anybody's
    // clone in order to take them away again.
    const notARepo = mkdtempSync(join(tmpdir(), 'vg-no-git-repo-'));
    tempRoots.push(notARepo);
    const result = runLint(site, ['--tag-repo', notARepo]);
    expect(result.status).toBe(1);
    expect(result.output).toContain('could not determine which rules have SHIPPED');
    expect(result.output).toContain('could not list git tags');
    expect(result.output).toContain('This is a FAILURE and not a skip');
    // And it must not have quietly gone on to report an OK line as well.
    expect(result.output).not.toContain('site copy lint OK');
  });

  it('refuses an override that hands it no rule IDs at all', () => {
    const site = makeSite();
    const emptyFile = join(site, 'empty-released-ids.json');
    writeFileSync(emptyFile, '[]', 'utf8');
    const result = runLint(site, ['--released-ids', emptyFile]);
    expect(result.status).toBe(1);
    expect(result.output).toContain('contains none');
    expect(result.output).toContain('An empty override is not an answer');
  });

  it('names the released set it used and where it came from', () => {
    const result = runLint(makeSite());
    expect(result.output).toContain('released set from');
    expect(result.output).toContain(FIXTURE_RELEASE_TAG);
    expect(result.output).toContain(`(${FIXTURE_RELEASED_IDS.length} shipped)`);
  });
});

// ── The generated data itself: present, and the one the artefact came from ──
//
// Two defects lived here, and they are the same defect in two modes.
//
// A MISSING `src/data/rules.json` was a note on an exit-0 run — one paragraph
// after R4's own header says it refuses to run when it cannot resolve which
// rules shipped. The cross-check simply did not happen and the log said OK.
//
// In ARTEFACT mode the cross-check reads `SITE_DIR/src/data/rules.json`, which
// is a SOURCE file: it answered a question about the working tree while the run
// claimed to be checking what will be served. Nothing in the built HTML names a
// release, so the artefact is tied to that file through the one thing it does
// carry — the rule IDs it rendered — and the two are now compared in both
// directions.
describe('R4 generated data: present, and the data the artefact was built from', () => {
  it('fails when the generated rules.json does not exist at all', () => {
    const site = makeSite();
    rmSync(join(site, 'src/data/rules.json'));
    const result = runLint(site);
    expect(result.status).toBe(1);
    expect(result.output).toContain('This is a FAILURE and not a note');
    expect(result.output).not.toContain('site copy lint OK');
  });

  it('fails in artefact mode on an ID the built pages render and the data does not hold', () => {
    const site = makeSite();
    // dist/ built from data that listed one more rule than the tree now holds.
    // VG-SMELL-020 is released and registered, so every other half of R4 is
    // happy with it: only the artefact-to-data link can object.
    write(
      site,
      'dist/rules/index.html',
      [
        '<!doctype html>',
        '<html lang="en"><head><meta charset="utf-8" /><title>Rules</title></head>',
        '<body>',
        '<main id="main">VG-AUTH-001 is one of them, and so is VG-SMELL-020.</main>',
        '<footer><a href="/install">Install</a></footer>',
        '</body></html>',
        '',
      ].join('\n'),
    );
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('do not describe the same rule set');
    expect(result.output).toContain('Only in the built HTML (1): VG-SMELL-020');
  });

  it('fails in artefact mode on an ID the data holds and the built pages never render', () => {
    const site = makeSite();
    write(
      site,
      'src/data/rules.json',
      JSON.stringify(
        {
          releaseTag: FIXTURE_RELEASE_TAG,
          rules: [{ ruleId: 'VG-AUTH-001' }, { ruleId: 'VG-SMELL-020' }],
        },
        null,
        2,
      ),
    );
    const result = runLint(site, ['--dist']);
    expect(result.status).toBe(1);
    expect(result.output).toContain('Only in the generated data (1): VG-SMELL-020');
  });

  it('says in the artefact summary that the built pages and the data agree', () => {
    const result = runLint(makeSite(), ['--dist']);
    expect(result.status).toBe(0);
    expect(result.output).toMatch(/built pages render the same \d+ ID\(s\) the generated data holds/);
  });
});

// ── The producing side of the field the linter reads ───────────────────
//
// ★ THE HALF THAT DID NOT EXIST. Everything above tests what the LINTER does
// with `releaseTag`. Nothing tested that `site-export-rules.mjs` writes it —
// the field appeared in this file only inside consumer-side fixtures the test
// author typed by hand. Deleting `releaseTag` from the generator's payload left
// the entire suite green, and the stale-data cross-check degraded to a note on
// a passing run: a whole guard removed, reported as OK.
//
// So there are two controls, and the first one runs everywhere. A checkout with
// no tags or unbuilt packages cannot run the generator at all, and "the guard
// only works where the generator runs" would put this back where it started.
describe('site-export-rules writes the release it filtered by', () => {
  const EXPORTER = join(SCRIPTS_DIR, 'site-export-rules.mjs');

  it('binds releaseTag in the payload it writes, from the release gate', () => {
    const source = readFileSync(EXPORTER, 'utf8');
    const payload = /const payload = \{([\s\S]*?)\n\};/.exec(source);
    expect(payload, 'the payload literal in site-export-rules.mjs could not be found').not.toBeNull();
    // The field is in the written object …
    expect(payload![1], 'site-export-rules.mjs writes no releaseTag field').toMatch(
      /^\s*releaseTag,\s*$/m,
    );
    // … and it is the gate's tag rather than some other value that happens to
    // share the name. Shorthand is what makes the second check cheap, and it is
    // also what makes the first one insufficient on its own.
    expect(source, 'releaseTag is no longer bound to the release gate').toMatch(
      /const \{ tag: releaseTag[^}]*\} = releaseGate\(\);/,
    );
  });

  const canRun = hasReleaseTag && existsSync(join(REPO_ROOT, 'packages', 'rules', 'dist', 'index.js'));
  const endToEndName = canRun
    ? 'writes a file whose releaseTag the linter then cross-checks against the same tag'
    : '!!! SKIPPED — GENERATOR NOT RUNNABLE HERE: ' +
      (hasReleaseTag
        ? 'packages/rules/dist is missing (npm run build -w @vibeguard/rules)'
        : 'this checkout resolved no release tag') +
      '; the producer-to-consumer loop was NOT run end to end. The static control above ' +
      'still holds';

  it.runIf(canRun)(endToEndName, () => {
    const out = join(mkdtempSync(join(tmpdir(), 'vg-export-rules-')), 'rules.json');
    tempRoots.push(dirname(out));
    execFileSync(process.execPath, [EXPORTER, '--out', out], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const written = JSON.parse(readFileSync(out, 'utf8')) as { releaseTag?: string };
    const { tag } = releasedRuleIds();
    expect(written.releaseTag, 'the generated payload carries no releaseTag').toBe(tag);

    // The loop closed: hand the generator's own output to the consumer that
    // reads the field, resolving the tag from the real repository rather than
    // from an injected set. This is the pair that was silently broken — one
    // side writing, the other reading, and no test on the join.
    const site = makeSite();
    cpSync(out, join(site, 'src', 'data', 'rules.json'));
    const result = runLint(site, ['--tag-repo', REPO_ROOT]);
    expect(result.output).toContain(`generated rules.json agrees it is ${tag}`);
    expect(result.status).toBe(0);
  });
});

// ── The module both the linter and the generator read ───────────────────────
//
// `site-release-tag.mjs` exists because R4 and `site-export-rules.mjs` used to
// answer "which rules have shipped" separately, and the site went out advertising
// four rules on the strength of that disagreement. These tests are of the answer
// itself, rather than of either caller's reaction to it.
describe('site-release-tag: which rules have shipped', () => {
  it('takes the newest release tag and ignores the moving and working ones', () => {
    // `v0` is what the GitHub Action resolves and `v0-remote-check` is a
    // working tag. Neither is a release, and neither is filtered by name.
    expect(pickReleaseTag('v0\nv0-remote-check\nv0.3.6\nv0.3.5\nv0.2.0\n')).toBe('v0.3.6');
  });

  it('refuses a tag list containing no release, rather than returning nothing', () => {
    // The branch a shallow or --no-tags checkout lands on. Returning an empty
    // set here is the whole accident in miniature: the generator would publish
    // a page with no rules on it and R4 would compare against nothing.
    expect(() => pickReleaseTag('v0\nv0-remote-check\n')).toThrow(
      /no release tag of the form vMAJOR\.MINOR\.PATCH/,
    );
    expect(() => pickReleaseTag('')).toThrow();
    try {
      pickReleaseTag('');
      expect.unreachable('pickReleaseTag accepted an empty tag list');
    } catch (error) {
      expect((error as { code?: string }).code).toBe('NO_RELEASE_TAG');
    }
  });

  // The real repository. Skipped, loudly and — since the defect this replaced
  // — accurately: `releaseTagAvailability` names WHICH of the two states this
  // checkout is in, and is unit-tested immediately below.
  it('names a git failure and a tagless checkout as different reasons to skip', () => {
    const gitBroke = releaseTagAvailability({ ok: false, failure: 'git: command not found' });
    expect(gitBroke.hasReleaseTag).toBe(false);
    expect(gitBroke.testName).toContain('GIT DID NOT ANSWER');
    expect(gitBroke.testName).toContain('git: command not found');
    // The misattribution itself: a failed call must not be reported as the
    // shallow-fetch case, which is the only one a deeper fetch repairs.
    expect(gitBroke.testName).not.toContain('vMAJOR.MINOR.PATCH');

    const noTags = releaseTagAvailability({ ok: true, tagList: '' });
    expect(noTags.hasReleaseTag).toBe(false);
    expect(noTags.testName).toContain('GIT ANSWERED WITH NO RELEASE TAG');
    expect(noTags.testName).toContain('0 tag(s)');

    const onlyMoving = releaseTagAvailability({ ok: true, tagList: 'v0\nv0-remote-check\n' });
    expect(onlyMoving.hasReleaseTag).toBe(false);
    expect(onlyMoving.testName).toContain('2 tag(s)');

    expect(releaseTagAvailability({ ok: true, tagList: 'v0\nv0.3.6\n' })).toEqual({
      hasReleaseTag: true,
      testName: 'reads a set out of the real repository that is a subset of the working tree',
    });
  });

  it.runIf(hasReleaseTag)(realRepoTest, () => {
    const { tag, ids } = releasedRuleIds();
    expect(tag).toMatch(/^v\d+\.\d+\.\d+$/);
    expect(ids.size).toBeGreaterThan(50);
    // VG-AUTH-001 is the rule the front page leads with, and has shipped in
    // every release the site has ever described.
    expect(ids.has('VG-AUTH-001')).toBe(true);

    // The other half of the claim this file used to make in a comment: that the
    // tag's source text contains unregistered candidates, VG-SMELL-031 among
    // them. It does not — the parse looks for `ruleId:` declarations and that ID
    // has never had one. Measured here rather than asserted in prose.
    expect(
      ids.has(PROSE_ONLY_RULE_ID),
      `${PROSE_ONLY_RULE_ID} is in the parse of ${tag}; the R4 comment about the registry half needs rewriting`,
    ).toBe(false);

    // The invariant that matters: a rule that shipped is a rule that is still
    // written down here. The opposite direction is the one that is allowed to
    // be non-empty, and is exactly what the gate withholds.
    const declaredNow = new Set<string>();
    for (const dir of [
      join(REPO_ROOT, 'packages', 'rules', 'src', 'rules'),
      join(REPO_ROOT, 'packages', 'analysis-graph', 'src', 'design-smells-crossfile'),
    ]) {
      for (const file of walkTs(dir)) {
        const text = readFileSync(file, 'utf8');
        const re = /ruleId: '(VG-[A-Z]+-\d+)'/g;
        for (let m = re.exec(text); m; m = re.exec(text)) declaredNow.add(m[1]);
      }
    }
    expect(declaredNow.size).toBeGreaterThan(ids.size - 1);
    const vanished = [...ids].filter((id) => !declaredNow.has(id));
    expect(vanished, `shipped at ${tag} but no longer declared in the working tree`).toEqual([]);
  });
});

/** Every .ts under `dir`, recursively. */
function walkTs(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkTs(full));
    else if (entry.name.endsWith('.ts')) out.push(full);
  }
  return out;
}

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

  // The generated data is the second input a developer legitimately may not
  // have, and the reason these two tests failed in CI while passing on every
  // machine that had run the site once.
  //
  // src/data/*.json is written by scripts/site-export-*.mjs and is git-ignored,
  // because a committed copy stops matching the product on the next release.
  // `npm test` does not run those generators — site-deploy.yml does, before it
  // lints. So in CI the pages render with no rule IDs at all, and R4's vacuity
  // guard fires exactly as designed: "no rule ID appears anywhere on the site".
  // That is the linter being right about a tree that has not been generated,
  // not a copy violation.
  //
  // Skipping is safe here in a way it would not be for the linter itself,
  // because the coverage is not lost: site-deploy.yml runs site-copy-lint in
  // BOTH modes against a fully generated tree on every push, which is the run
  // that actually gates a deploy. What is kept in `npm test` is the 48
  // fixture-based tests, which need no generated input and prove every rule can
  // fail. Same shape as the dist skip below: one condition, named in the test
  // title, shouting when it is not met.
  const hasGeneratedData = () => existsSync(join(REAL_SITE, 'src', 'data', 'rules.json'));
  const generated = hasGeneratedData();
  const needsData = (name: string) =>
    generated
      ? name
      : `!!! SKIPPED — NOT GENERATED: run the scripts/site-export-*.mjs generators; ${name}`;

  // Runs from the first day a page exists, and is the check that matters
  // day-to-day: whatever pages are present must contain no violation. It is
  // separated from the page-count assertion below so that an incomplete site
  // still gets its copy checked, instead of one big red blob that says nothing
  // about the words on the pages that do exist.
  it.runIf(generated)(needsData('contains no copy violation in whatever pages exist today'), (ctx) => {
    if (!hasGeneratedData()) {
      ctx.skip();
      return;
    }
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
  it.runIf(generated)(
    needsData(`passes source mode outright (site/src/pages currently holds ${pageCount} entries)`),
    (ctx) => {
      if (!hasGeneratedData()) {
        ctx.skip();
        return;
      }
      const result = runLint(REAL_SITE);
      expect(result.output).toContain('site copy lint OK, SOURCE mode');
      expect(result.status).toBe(0);
    },
  );

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
