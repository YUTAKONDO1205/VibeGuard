// A2 — no-egress assertion over the execution closure of the shipped code.
//
// SUBJECT OF THE CLAIM. Not "four distribution channels" — that phrasing counts
// marketing surfaces and quietly implies the GitHub Action is audited the same
// way the others are, which it is not (A2-GAP-4). What this file asserts over is
// the EXECUTION CLOSURE of the artefacts we scan: every JS/TS file a user can
// end up running from a VibeGuard install, plus the HTML and CSS the Chrome
// side panel loads (those egress without any JavaScript at all — see the
// markup section below). For the CLI that closure is not
// apps/cli/dist alone — `apps/cli/dist/index.js` is tsc output, not a bundle,
// and its very first import reaches into @vibeguard/analyzer-core, which pulls
// in the other workspace packages. Scanning only apps/cli/dist audited a handful
// of thin re-export files and left the analyzer itself outside the assertion.
// So `targets()` enumerates packages/*/dist as well, and the closure-completeness
// check below makes that enumeration self-policing rather than a list somebody
// has to remember to extend.
//
// WHAT THIS DEFENDS. PRIVACY.md claims「コードは端末外に出ない」and SCOPE.md §3
// A2 makes that claim part of the availability/confidentiality contribution
// (C4: the detector's own attack surface). A claim nobody can falsify is not a
// security property, it is marketing. This script turns it into a CI assertion:
// build the distributables, parse them, count network sinks, require zero.
//
// WHY NOT grep. The obvious implementation — `grep -R "fetch(" dist/` — is
// actively wrong here and would have to be neutered into uselessness. The
// analyzer ships rule definitions whose whole job is to RECOGNISE `fetch`,
// `http`, `eval`; those rule patterns are string literals inside the bundle, so
// a textual grep over dist/ lights up on VibeGuard's own detection logic. The
// only way to distinguish "the bundle mentions fetch" from "the bundle CALLS
// fetch" is to look at the syntax tree. So the unit of detection here is a
// CallExpression / NewExpression / import specifier — never a substring.
//
// PARSER CHOICE. `typescript` (TypeScript 5.x, `ts.createSourceFile`). It is a
// declared root devDependency, so this script adds no dependency at all, and it
// is not a runtime dependency of anything we ship. acorn is present in
// node_modules too but only transitively (acorn-walk ← mlly ← vitest), and
// depending on a transitive package is how a "verified" check quietly breaks on
// the next lockfile refresh.
//
// VACUOUS-PASS DEFENCE. A scanner that looks at nothing reports zero sinks and
// exits green. There are four distinct ways to look at nothing, and each needs
// its own guard:
//   1. Scanning a target too thinly. Every target declares a minimum file
//      count; scanning fewer files fails.
//   2. A broken detector. `--mode control` feeds seeded-violation fixtures
//      (scripts/fixtures/a2-egress/) through the SAME detector and requires
//      each one to be caught. If the detector is blinded, the control goes red.
//   3. Scanning stale bytes. CI builds and packages in the same job, so a
//      committed dist from three commits ago cannot be what got scanned.
//   4. NOT SCANNING A DIRECTORY AT ALL. This is the one the first three are
//      blind to, and it is the failure this file actually shipped with: an
//      `await fetch(...)` appended to packages/analyzer-core/dist/index.js used
//      to leave `--mode dist` green, because `targets()` listed only apps/cli/
//      dist, extensions/vscode/dist and extensions/chrome/dist. minFiles is
//      satisfied by the files we DID scan; the control fixtures pass because
//      the detector was never broken; freshness is irrelevant to bytes nobody
//      opened. A file-count floor cannot floor a directory that is not in the
//      list. The guard for (4) is therefore structural rather than numeric:
//      `checkClosureCompleteness()` requires every package that `--mode deps`
//      waved through on the strength of its NAME to also be a directory this
//      script opened and parsed. Adding a sixth @vibeguard/* package fails CI
//      until it is scanned. Nothing here defends against a distributable whose
//      execution closure escapes the workspace entirely — that is what the
//      production dependency allowlist is for.
//
// MODES
//   --mode dist     (default) AST-scan the execution closure + manifest lock
//   --mode control  negative control: seeded fixtures MUST be detected
//   --mode deps     production dependency allowlist + closure completeness
//   --mode compare  --a x.json --b y.json: findings equal modulo findingId
//   --mode all      dist + control + deps
//
// FLAGS
//   --cli-dir <dir>     scan an unpacked `npm pack` tarball instead of apps/cli/dist
//   --vscode-dir <dir>  scan an extracted .vsix instead of extensions/vscode/dist
//   --chrome-dir <dir>  scan an unzipped Chrome bundle instead of extensions/chrome/dist
//   --out <path>        write the JSON report (default under _results/)
//   --quiet             suppress the per-target console table
//
// CI points the three --*-dir flags at the artifacts release.yml actually
// publishes (unpacked tarball / unzipped .vsix / unzipped Chrome bundle), so
// what gets audited is the shipped bytes rather than a build tree that happens
// to sit next to them. Locally the defaults keep it a one-command check.
//
// Run:  npm run build && node scripts/sec-a2-egress-scan.mjs --mode all
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import ts from 'typescript';

const REPO_ROOT = resolve(dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');

// ── Sink taxonomy ────────────────────────────────────────────────────────────
//
// Everything below is matched on the *syntactic* shape of a call/new/import,
// never on text. The lists are deliberately over-broad on the callee name side:
// we match by the final identifier, so `globalThis.fetch(...)`, `w.fetch(...)`
// and a minifier's `a.fetch(...)` all count. Over-matching produces false
// alarms that a human resolves once; under-matching produces a silent green,
// which is the failure mode this whole file exists to prevent.

/** Callables that perform, or directly arm, an outbound request. */
const NET_CALLEES = new Set([
  'fetch',
  'sendBeacon', // navigator.sendBeacon — the classic exfil primitive
  'importScripts', // worker-scope remote code load
]);

/** Constructors that create a network channel. */
const NET_CONSTRUCTORS = new Set([
  'XMLHttpRequest',
  'WebSocket',
  'EventSource',
  'Image', // `new Image().src = url` is egress with no fetch in sight
  'Request', // only exists to be handed to fetch()
  'Audio', // same trick as Image
  'SharedWorker',
]);

/**
 * Node core modules that expose a socket. `node:`-prefixed forms are stripped
 * before lookup. Note the absentees: `fs`, `path`, `url` are not sinks and
 * flagging them would drown the real signal.
 */
const NODE_NET_MODULES = new Set([
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dgram',
  'dns',
  'dns/promises',
  'inspector',
  'cluster', // spawns IPC-connected children; cheap to forbid, we never use it
]);

/**
 * URL schemes that cannot leave the machine. Everything else — including the
 * scheme-relative `//host/x` form — is treated as egress.
 *
 * `chrome-extension:`/`moz-extension:` resolve inside the packaged extension
 * itself, so they are same-package references rather than network fetches.
 * `javascript:` is a scripting sink, not an egress one; it is out of A2's scope
 * and flagging it here would blur what the PASS line means.
 */
const LOCAL_URL_SCHEMES = new Set(['data', 'blob', 'about', 'javascript', 'chrome-extension', 'moz-extension']);

/**
 * Does this attribute/property value name something off the machine?
 *
 * This — not the attribute name — is the discriminator for markup. Every HTML
 * document worth shipping is full of `src=` and `href=`; what distinguishes
 * `index.css` from `https://evil.invalid/x.js` is the scheme, so the check is
 * built around it and relative paths cost nothing to allow.
 */
function isExternalUrl(raw) {
  if (typeof raw !== 'string') return false;
  const v = raw.trim().replace(/^["']|["']$/g, '').trim();
  if (v === '') return false;
  if (v.startsWith('//')) return true; // protocol-relative: inherits http(s) from the page
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(v);
  if (!m) return false; // relative path, fragment, or query — stays inside the package
  return !LOCAL_URL_SCHEMES.has(m[1].toLowerCase());
}

/** Elements whose `src`/`href` fetches a remote resource when injected. */
const REMOTE_LOADING_TAGS = new Set(['script', 'img', 'iframe', 'link', 'object', 'embed', 'video', 'audio', 'source']);

/**
 * Attribute names that turn a DOM node into a request. Assigning any of these,
 * whether via `el.src = x` or `el.setAttribute('src', x)`, is treated as a
 * potential exfil channel.
 */
const REMOTE_LOADING_ATTRS = new Set([
  'src',
  'srcset',
  'href',
  // Inline SVG reaches the network through the SVG 1.1 attribute, not `src`:
  // `<image xlink:href="https://…">` and `<use xlink:href="…">` both fetch, and
  // inline SVG is written directly into HTML. `parseAttributes` lower-cases the
  // name and its pattern already admits `:`, so the only thing missing was the
  // entry here.
  'xlink:href',
  'data',
  'action',
  'formaction',
  'poster',
]);

/**
 * `href` is the odd one out: on most elements it loads (a stylesheet, a
 * prefetch), but on `<a>` and `<area>` it is a NAVIGATION target the user has to
 * click. A documentation link in the side panel fetches nothing at load time, so
 * flagging it would make an ordinary UI edit fail the egress gate — a false
 * alarm that trains people to weaken the check.
 *
 * `<base href>` is deliberately NOT here: it rewrites every relative URL on the
 * page to a remote origin, which is the strongest load-time egress a single tag
 * can express.
 */
const NAVIGATION_ONLY_HREF_TAGS = new Set(['a', 'area']);

/**
 * Justified exceptions. Empty on purpose — an entry here is an admission that
 * a distributable contains a network sink, so each one must carry a reason and
 * be reviewed. Shape: { target, file, line, sink, reason }. Matching is exact
 * on target+file+sink+line so a moved or mutated sink stops being exempt.
 */
const ALLOWLIST = [];

// ── Known gaps ───────────────────────────────────────────────────────────────
//
// Everything this scanner cannot see, declared in one place and printed on
// EVERY run regardless of mode. The reason for the "every run" part: the worst
// possible behaviour for an auditing tool is to encounter something it cannot
// parse and silently count it as zero. A reader who sees "A2: PASS" and does
// not also see this list will reasonably conclude the artefacts were audited in
// full, and that conclusion would be false. These are not TODOs to be quietly
// closed by narrowing the claim; they are the boundary of the claim.
const KNOWN_GAPS = [
  {
    id: 'A2-GAP-1',
    scope: 'chrome-manifest',
    what: 'host_permissions is <all_urls>',
    why: 'chrome.scripting.executeScript against the active tab needs a host grant',
    risk: 'it also authorises cross-origin fetch from the service worker, so the no-egress claim rests entirely on the AST scan above, not on the permission set',
    fix: 'move to activeTab-only injection, or narrow to the origins the side panel supports',
  },
  {
    id: 'A2-GAP-2',
    scope: 'chrome-manifest',
    what: "no content_security_policy.extension_pages, so connect-src is unrestricted",
    why: 'MV3 default CSP constrains script-src/object-src only',
    risk: 'a future XSS in the side panel could reach the network even though today no code does',
    fix: "add \"content_security_policy\": { \"extension_pages\": \"script-src 'self'; object-src 'self'; connect-src 'none'\" }",
  },
  {
    id: 'A2-GAP-3',
    scope: 'scanner-coverage',
    // NARROWED, not closed. The original gap was total — .html and .css were
    // not opened at all. They are now walked and scanned (scanHtml/scanCss),
    // static remote references are caught, and inline <script>/on* handlers go
    // through the same AST as shipped JS. What is written below is only what
    // remains, and it remains declared because a partially closed gap reported
    // as closed is worse than one reported as open.
    what: 'HTML and CSS are scanned STATICALLY only — markup that does not exist until runtime is outside the assertion',
    why: 'scanHtml()/scanCss() read the bytes on disk. A remote reference that is assembled at runtime is not in those bytes: markup built by JS and injected via innerHTML/insertAdjacentHTML, a stylesheet built with CSSOM (insertRule) or a style attribute written from script, and any URL assembled from fragments. The JS half of the AST scan is what covers those paths, and it covers them by their sink shape (dom-attr-assign, dom-element-create, net-call) rather than by reading the resulting URL, so it cannot tell an external destination from a local one',
    risk: "a side panel that does `el.innerHTML = '<img src=' + host + '>'` is caught by the AST leg only if the sink shape survives; a purely computed one (e.g. a URL built into a variable then handed to an API this taxonomy does not list) would be seen by neither leg. Also unscanned: the .png icons (binary, no URL syntax) and manifest.json (covered instead by the permission baseline, not by a URL scan). SEPARATELY, the discriminator is the URL scheme as a LITERAL STRING, so any spelling a browser normalises but this scanner does not is a bypass of the audit rather than of the browser: HTML numeric character references ARE decoded (see decodeEntities, added after `&#104;ttps://` was found to scan clean), but CSS escapes (`url(\\68 ttps://…)`) and tab/newline inside a scheme are NOT",
    fix: 'no cheap complete fix exists — full coverage needs taint tracking from string construction to sink, which is a different tool. The honest bound is: every static, UNOBFUSCATED remote reference in shipped HTML/CSS is asserted zero; dynamically constructed ones rest on the JS sink taxonomy plus the manifest CSP gap (A2-GAP-2); and scheme-obfuscated ones are covered for HTML entities only. This leg is therefore sound against accidental egress and dependency drift, and NOT a defence against a hostile commit deliberately hiding a sink from the auditor — that is what code review of the diff is for',
  },
  {
    id: 'A2-GAP-4',
    scope: 'distribution',
    what: 'the GitHub Action (action.yml) is outside the offline-parity claim by construction',
    why: "action.yml is `using: 'composite'` and runs `npm ci` on the consumer's runner to fetch the CLI, so it REQUIRES the network to do its job",
    risk: '「ネットワークを剥がしても動く」cannot be asserted for the Action the way it is for the CLI, and asserting it anyway would be false. The Action is a thin wrapper that acquires the CLI over npm; what it acquires is the very execution closure asserted above, but the acquisition step itself is a network operation and the registry is a trusted third party',
    fix: 'nothing to fix in the Action — the honest framing is that A2 covers the AST-scanned execution closure, and the Action inherits that closure only after npm has delivered it. Supply-chain integrity of the delivery is a separate property (provenance/attestation), not A2',
  },
];

// ── AST walk ─────────────────────────────────────────────────────────────────

/** Final identifier of a callee expression: `a.b.fetch` → 'fetch'. */
function calleeName(expr) {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  if (ts.isElementAccessExpression(expr) && ts.isStringLiteralLike(expr.argumentExpression)) {
    return expr.argumentExpression.text;
  }
  if (ts.isParenthesizedExpression(expr)) return calleeName(expr.expression);
  return undefined;
}

/** Module specifier normalised for NODE_NET_MODULES lookup. */
function normaliseModule(spec) {
  return spec.startsWith('node:') ? spec.slice(5) : spec;
}

function literalText(node) {
  return node && ts.isStringLiteralLike(node) ? node.text : undefined;
}

/**
 * Parse one JS file and return every network sink in it.
 *
 * Parsed with ScriptKind.JS and no type information: we only need shapes, and
 * a full program build over bundled dist output would be slow and would demand
 * lib/type resolution we do not have for browser+node mixed targets.
 */
function scanSource(filePath, text) {
  // ScriptKind must follow the extension: the CLI tarball ships src/*.ts
  // alongside dist/*.js (apps/cli/package.json declares no `files` allowlist),
  // and parsing TypeScript as JS turns every type annotation into a syntax
  // error, which TS recovers from by discarding subtrees — silently shrinking
  // the region we searched. A quietly under-parsed file is a false negative.
  const kind = /\.(m|c)?ts$/.test(filePath) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sf = ts.createSourceFile(filePath, text, ts.ScriptTarget.Latest, /* setParentNodes */ true, kind);
  const hits = [];

  const at = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const push = (node, sink, detail) => hits.push({ line: at(node), sink, detail });

  const visit = (node) => {
    // (ii) static imports: `import x from 'https'` / `export … from 'net'`
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      const spec = literalText(node.moduleSpecifier);
      if (spec && NODE_NET_MODULES.has(normaliseModule(spec))) push(node, 'node-net-import', spec);
    }
    // `import x = require('net')` (TS-style, survives some bundlers)
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      const spec = literalText(node.moduleReference.expression);
      if (spec && NODE_NET_MODULES.has(normaliseModule(spec))) push(node, 'node-net-import', spec);
    }

    if (ts.isCallExpression(node)) {
      // Dynamic import + CommonJS require of a socket module.
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const name = calleeName(node.expression);
      if (isDynamicImport || name === 'require' || name === 'createRequire') {
        const spec = literalText(node.arguments[0]);
        if (spec && NODE_NET_MODULES.has(normaliseModule(spec))) {
          push(node, 'node-net-import', spec);
        } else if (!spec && node.arguments.length > 0) {
          // A computed specifier can resolve to anything at runtime, so it is
          // itself the finding: it defeats this whole analysis.
          push(node, 'dynamic-module-specifier', ts.SyntaxKind[node.arguments[0].kind]);
        }
      }

      // (i) direct network calls.
      if (name && NET_CALLEES.has(name)) push(node, 'net-call', name);

      // (iii) DOM sinks that fetch a remote resource.
      if (name === 'createElement') {
        const tag = literalText(node.arguments[0]);
        if (tag && REMOTE_LOADING_TAGS.has(tag.toLowerCase())) push(node, 'dom-element-create', tag);
      }
      if (name === 'setAttribute' || name === 'setAttributeNS') {
        const attr = literalText(node.arguments[name === 'setAttributeNS' ? 1 : 0]);
        if (attr && REMOTE_LOADING_ATTRS.has(attr.toLowerCase())) push(node, 'dom-attr-set', attr);
      }
    }

    // (i)/(iii) constructors that open a channel.
    if (ts.isNewExpression(node)) {
      const name = calleeName(node.expression);
      if (name && NET_CONSTRUCTORS.has(name)) push(node, 'net-construct', name);
    }

    // (iii) `el.src = …` — assignment, not a call, so the call visitor misses it.
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      REMOTE_LOADING_ATTRS.has(node.left.name.text.toLowerCase())
    ) {
      push(node, 'dom-attr-assign', node.left.name.text);
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return hits;
}

// ── Markup and stylesheet scan ───────────────────────────────────────────────
//
// WHY THESE FILES AT ALL. extensions/chrome/dist ships sidepanel/index.html and
// sidepanel/index.css, and manifest.json points side_panel.default_path at the
// HTML. A single `<img src="https://…/p.gif?d=CODE">` in that file exfiltrates
// with no JavaScript anywhere in the closure, and the AST scan above would keep
// reporting a clean zero — the zero of not having looked. That was A2-GAP-3.
//
// WHY REGEX HERE WHEN grep WAS REJECTED FOR JS. The argument against grepping
// JS was not "regexes are crude", it was that the discriminator was unavailable
// to a regex: the bundle legitimately CONTAINS the string `fetch(` inside rule
// definitions, and only the syntax tree separates "mentions" from "calls".
// Markup does not have that problem, because the discriminator here is the URL
// SCHEME rather than an identifier name. A rule pattern, a placeholder, or a
// paragraph of prose may say `src` or `url(` as often as it likes; what gets
// flagged is a value that resolves off-machine, and no VibeGuard rule payload
// carries one of those. The residual risk of a regex over markup is the mirror
// image of grep-over-JS: over-matching (a `<img src=https://…>` written inside
// an HTML comment or a text node) rather than under-matching. Over-matching
// costs a human one look; under-matching is the silent green this whole file
// exists to prevent, so the trade is taken deliberately in that direction. The
// one place markup carries real code — inline <script> and on* handlers — is
// NOT regexed for sinks: its contents are handed to scanSource() and get the
// same AST treatment as any shipped .js.
//
// Adding an HTML parser (parse5 et al) would buy tolerance of malformed markup
// we do not ship, at the cost of a new dependency in the audit path — and a
// dependency in the auditor is itself un-audited surface.

/** 1-based line number of a character offset. */
function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/** Minimal entity decode, enough to read a URL out of an attribute value. */
function decodeEntities(s) {
  return (
    s
      // Numeric character references, decimal and hex, BEFORE the named ones so
      // that `&#38;#104;` style double-encoding does not resolve into a live
      // `&amp;`-decoded scheme on the second pass.
      //
      // This is not cosmetic. The whole markup leg discriminates on the URL
      // SCHEME as a literal string (`isExternalUrl`), so anything that breaks
      // the literal `https:` while a browser still resolves it is a bypass of
      // the audit, not of the browser. `<img src="&#104;ttps://evil.invalid/x">`
      // fetches exactly as if it were spelled out, and without this replace the
      // scanner classified it as a relative path and stayed green.
      //
      // The trailing `;` is optional in HTML for numeric references, and browsers
      // accept the truncated form, so it is optional here too.
      .replace(/&#(\d+);?/g, (_, d) => safeFromCodePoint(Number(d)))
      .replace(/&#[xX]([0-9a-fA-F]+);?/g, (_, h) => safeFromCodePoint(parseInt(h, 16)))
      .replace(/&(?:amp|AMP);/g, '&')
      .replace(/&(?:quot|QUOT);/g, '"')
      .replace(/&(?:apos|APOS);/g, "'")
      .replace(/&(?:lt|LT);/g, '<')
      .replace(/&(?:gt|GT);/g, '>')
  );
}

/**
 * `String.fromCodePoint` throws on out-of-range values, and a malformed
 * reference in a distributable must not crash the audit — a scanner that dies
 * on hostile input reports nothing, which reads the same as reporting zero.
 * Undecodable references are left to fail the scheme match, i.e. treated as
 * "not an external URL", which is the same answer the pre-fix scanner gave.
 */
function safeFromCodePoint(cp) {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return '';
  try {
    return String.fromCodePoint(cp);
  } catch {
    return '';
  }
}

/**
 * Blank out a region while preserving newlines, so every later offset still maps
 * to the line it came from. Used for comments: markup inside `<!-- -->` or
 * `/* *\/` is inert, and flagging it would train readers to ignore the tool.
 */
function blankPreservingLines(text, re) {
  return text.replace(re, (m) => m.replace(/[^\n]/g, ' '));
}

/** Attributes of one tag, as [{ name, value, index }] with source offsets. */
function parseAttributes(attrText, baseIndex) {
  const out = [];
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'`=<>]+))/g;
  let m;
  while ((m = re.exec(attrText)) !== null) {
    const value = m[3] ?? m[4] ?? m[5] ?? '';
    out.push({ name: m[1].toLowerCase(), value: decodeEntities(value), index: baseIndex + m.index });
  }
  return out;
}

/**
 * Parse one HTML file and return every egress sink in it.
 *
 * Sink classes:
 *   html-remote-ref  a remote-loading element points at an external origin
 *   html-meta-refresh  <meta http-equiv=refresh> redirects off-origin
 *   plus whatever scanSource() finds inside inline <script> and on* handlers.
 */
function scanHtml(filePath, rawText) {
  const hits = [];
  const text = blankPreservingLines(rawText, /<!--[\s\S]*?-->/g);

  // Inline <script> bodies first: a script element with no src is JavaScript,
  // and JavaScript gets the AST, not the regex.
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let sm;
  while ((sm = scriptRe.exec(text)) !== null) {
    const attrs = parseAttributes(sm[1], sm.index);
    const body = sm[2];
    if (attrs.some((a) => a.name === 'src')) continue; // handled by the element pass below
    if (body.trim() === '') continue;
    const type = attrs.find((a) => a.name === 'type')?.value?.toLowerCase();
    // Non-executable <script> payloads (JSON-LD, templates) are data. Parsing
    // them as JS would be noise; they cannot fetch anything on their own.
    if (type && !/^(module|text\/javascript|application\/javascript)$/.test(type)) continue;
    const bodyLine = lineAt(text, sm.index + sm[0].indexOf(body));
    for (const hit of scanSource(`${filePath}#inline-script`, body)) {
      hits.push({ line: bodyLine + hit.line - 1, sink: hit.sink, detail: `inline <script>: ${hit.detail}` });
    }
  }

  const tagRe = /<([a-zA-Z][-a-zA-Z0-9]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;
  let tm;
  while ((tm = tagRe.exec(text)) !== null) {
    const tag = tm[1].toLowerCase();
    const attrs = parseAttributes(tm[2], tm.index + tm[1].length + 1);
    for (const a of attrs) {
      // Event handler attributes carry JavaScript. Same rule as <script>: give
      // it to the parser rather than pattern-matching a URL out of it.
      if (a.name.startsWith('on') && a.value.trim() !== '') {
        for (const hit of scanSource(`${filePath}#${a.name}`, a.value)) {
          hits.push({ line: lineAt(text, a.index), sink: hit.sink, detail: `${tag}[${a.name}]: ${hit.detail}` });
        }
        continue;
      }
      if (!REMOTE_LOADING_ATTRS.has(a.name)) continue;
      if (a.name === 'href' && NAVIGATION_ONLY_HREF_TAGS.has(tag)) continue;
      // srcset carries a comma-separated candidate list; each candidate is a
      // URL followed by an optional descriptor.
      const candidates =
        a.name === 'srcset' ? a.value.split(',').map((c) => c.trim().split(/\s+/)[0]) : [a.value];
      for (const url of candidates) {
        if (!isExternalUrl(url)) continue;
        const rel = attrs.find((x) => x.name === 'rel')?.value;
        hits.push({
          line: lineAt(text, a.index),
          sink: 'html-remote-ref',
          detail: `<${tag}${rel ? ` rel=${rel}` : ''} ${a.name}="${url}">`,
        });
      }
    }
    if (tag === 'meta') {
      const equiv = attrs.find((a) => a.name === 'http-equiv')?.value?.toLowerCase();
      const content = attrs.find((a) => a.name === 'content')?.value ?? '';
      if (equiv === 'refresh') {
        const target = /url\s*=\s*(.+)$/i.exec(content)?.[1];
        if (isExternalUrl(target ?? '')) {
          hits.push({ line: lineAt(text, tm.index), sink: 'html-meta-refresh', detail: content });
        }
      }
    }
  }
  return hits;
}

/**
 * Parse one CSS file and return every egress sink in it.
 *
 * `url(...)` covers @font-face src, background-image, cursor, image-set and
 * every other property that takes one, because the function form is the same
 * everywhere. `@import` gets its own pass since it also accepts a bare string.
 */
function scanCss(filePath, rawText) {
  const hits = [];
  const text = blankPreservingLines(rawText, /\/\*[\s\S]*?\*\//g);

  const urlRe = /url\(\s*("([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi;
  let m;
  while ((m = urlRe.exec(text)) !== null) {
    const value = (m[2] ?? m[3] ?? m[4] ?? '').trim();
    if (isExternalUrl(value)) hits.push({ line: lineAt(text, m.index), sink: 'css-remote-ref', detail: `url(${value})` });
  }

  const importRe = /@import\s+(?:url\(\s*("([^"]*)"|'([^']*)'|([^)]*))\s*\)|"([^"]*)"|'([^']*)')/gi;
  while ((m = importRe.exec(text)) !== null) {
    const value = (m[2] ?? m[3] ?? m[4] ?? m[5] ?? m[6] ?? '').trim();
    if (isExternalUrl(value)) hits.push({ line: lineAt(text, m.index), sink: 'css-import', detail: `@import ${value}` });
  }
  return hits;
}

/** Dispatch one file to the scanner its extension calls for. */
function scanFile(filePath, text) {
  if (/\.html?$/i.test(filePath)) return scanHtml(filePath, text);
  if (/\.css$/i.test(filePath)) return scanCss(filePath, text);
  return scanSource(filePath, text);
}

// ── Target definitions ───────────────────────────────────────────────────────

function walkScannable(root) {
  const out = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) {
        stack.push(full);
        continue;
      }
      // Source maps are not executed, and .d.ts files are declarations with no
      // call sites. Everything else that a consumer could run, compile, or LOAD
      // is in scope — the .ts sources the CLI tarball ships, and the HTML/CSS
      // the Chrome side panel is made of, which egress without any JS at all.
      if (/\.d\.(m|c)?ts$/.test(name)) continue;
      if (!/\.(js|mjs|cjs|ts|mts|cts|html?|css)$/i.test(name)) continue;
      out.push(full);
    }
  }
  return out.sort();
}

/**
 * `minFiles` encodes what each target is known to contain, so a wrong path or a
 * half-finished build reports "scanned 0 files" as a FAILURE instead of as a
 * clean bill of health. Bump these when a target legitimately grows; never
 * lower them to make a red build go away.
 *
 * `packageName` is what makes this list self-policing. Any target that IS a
 * published workspace package carries its npm name here, and
 * checkClosureCompleteness() cross-references those names against the
 * production dependency closure. A package that `--mode deps` accepted purely
 * because its name matched `@vibeguard/` but that appears in no target is a
 * hard failure — that combination is precisely "trusted without being read".
 *
 * The three shipped-artefact targets accept a --*-dir override so CI can point
 * them at the unpacked tarball / .vsix / zip. The workspace package targets do
 * NOT: their bytes are never repackaged (the CLI tarball does not vendor them;
 * `npm i` resolves them from the registry), so the build tree is the only place
 * this script can read them. That means for the packages the scanned bytes are
 * the ones CI just built rather than the ones npm would publish — an honest
 * difference, bounded by the fact that both come from the same tsc invocation
 * on the same commit in the same job.
 */
function targets(opts) {
  return [
    { id: 'cli', dir: opts.cliDir ?? resolve(REPO_ROOT, 'apps/cli/dist'), minFiles: 5, packageName: '@vibeguard/cli' },
    { id: 'vscode', dir: opts.vscodeDir ?? resolve(REPO_ROOT, 'extensions/vscode/dist'), minFiles: 1 },
    // 4 = background.js, sidepanel/index.js, sidepanel/index.html,
    // sidepanel/index.css. The floor was 2 while only JS was admitted; leaving
    // it at 2 after teaching walkScannable() about markup would have let the
    // side panel's HTML and CSS silently drop out of the scan again — exactly
    // the vacuous pass this floor exists to catch — since the two .js files
    // alone still satisfied it.
    { id: 'chrome', dir: opts.chromeDir ?? resolve(REPO_ROOT, 'extensions/chrome/dist'), minFiles: 4 },
    // The transitive closure of `import … from '@vibeguard/analyzer-core'`.
    // These floors are set below the current file counts (41/20/2/3/2 as of
    // 2026-07-20) so that ordinary refactoring does not go red, but far enough
    // above zero that a missing or empty dist cannot pass as clean.
    {
      id: 'pkg-analyzer-core',
      dir: resolve(REPO_ROOT, 'packages/analyzer-core/dist'),
      minFiles: 20,
      packageName: '@vibeguard/analyzer-core',
    },
    { id: 'pkg-rules', dir: resolve(REPO_ROOT, 'packages/rules/dist'), minFiles: 10, packageName: '@vibeguard/rules' },
    {
      id: 'pkg-findings-schema',
      dir: resolve(REPO_ROOT, 'packages/findings-schema/dist'),
      minFiles: 1,
      packageName: '@vibeguard/findings-schema',
    },
    {
      id: 'pkg-remediation-engine',
      dir: resolve(REPO_ROOT, 'packages/remediation-engine/dist'),
      minFiles: 1,
      packageName: '@vibeguard/remediation-engine',
    },
    {
      id: 'pkg-sarif-adapter',
      dir: resolve(REPO_ROOT, 'packages/sarif-adapter/dist'),
      minFiles: 1,
      packageName: '@vibeguard/sarif-adapter',
    },
  ];
}

function isAllowlisted(target, file, hit) {
  return ALLOWLIST.some(
    (a) => a.target === target && a.file === file && a.sink === hit.sink && a.line === hit.line,
  );
}

function scanTarget(t) {
  if (!existsSync(t.dir)) {
    return { id: t.id, dir: t.dir, ok: false, error: `missing directory — run \`npm run build\` first`, files: 0, hits: [] };
  }
  const files = walkScannable(t.dir);
  const hits = [];
  for (const file of files) {
    const rel = relative(REPO_ROOT, file).split(sep).join('/');
    for (const hit of scanFile(file, readFileSync(file, 'utf8'))) {
      if (isAllowlisted(t.id, rel, hit)) continue;
      hits.push({ file: rel, ...hit });
    }
  }
  const enough = files.length >= t.minFiles;
  return {
    id: t.id,
    dir: relative(REPO_ROOT, t.dir).split(sep).join('/'),
    files: files.length,
    minFiles: t.minFiles,
    hits,
    ok: enough && hits.length === 0,
    error: enough ? undefined : `scanned ${files.length} files, expected >= ${t.minFiles} (vacuous pass guard)`,
  };
}

// ── Chrome manifest lock ─────────────────────────────────────────────────────
//
// The AST scan proves the shipped Chrome code contains no sink. That is not the
// whole story for an extension: MV3 permissions decide what a sink COULD reach
// if one were introduced, and a permission can be widened in a one-line diff
// that no code review flags. So we lock the egress-relevant surface to a
// recorded baseline and fail on growth.
//
// Honesty note, deliberately not swept under the rug: `host_permissions` is
// currently `<all_urls>`, which is exactly the grant that would let a service
// worker `fetch()` any origin. It is there because the "extract from page"
// feature calls `chrome.scripting.executeScript` against the active tab.
// Narrowing it is tracked as a known gap (below) — it is NOT asserted away.
// The assertion this file can honestly make is: no code performs egress, and
// the permission set does not grow without someone editing this baseline.
const CHROME_MANIFEST_BASELINE = {
  permissions: ['activeTab', 'contextMenus', 'scripting', 'sidePanel', 'storage'],
  hostPermissions: ['<all_urls>'],
  // Derived from the single KNOWN_GAPS registry rather than duplicated, so the
  // manifest section of the JSON report keeps its shape while there remains
  // exactly one place a gap can be declared or retired.
  knownGaps: KNOWN_GAPS.filter((g) => g.scope === 'chrome-manifest'),
};

function checkChromeManifest(opts) {
  const dir = opts.chromeDir ?? resolve(REPO_ROOT, 'extensions/chrome/dist');
  const path = join(dir, 'manifest.json');
  if (!existsSync(path)) {
    return { ok: false, error: `${path} missing — run \`npm run build\`` };
  }
  const m = JSON.parse(readFileSync(path, 'utf8'));
  const perms = [...(m.permissions ?? [])].sort();
  const hosts = [...(m.host_permissions ?? [])].sort();
  const csp = m.content_security_policy?.extension_pages ?? null;

  const newPerms = perms.filter((p) => !CHROME_MANIFEST_BASELINE.permissions.includes(p));
  const newHosts = hosts.filter((h) => !CHROME_MANIFEST_BASELINE.hostPermissions.includes(h));

  // Dropping a permission is a tightening: record it, do not fail on it.
  const dropped = [
    ...CHROME_MANIFEST_BASELINE.permissions.filter((p) => !perms.includes(p)),
    ...CHROME_MANIFEST_BASELINE.hostPermissions.filter((h) => !hosts.includes(h)),
  ];

  return {
    ok: newPerms.length === 0 && newHosts.length === 0,
    permissions: perms,
    hostPermissions: hosts,
    contentSecurityPolicy: csp,
    addedBeyondBaseline: [...newPerms, ...newHosts],
    tightenedSinceBaseline: dropped,
    knownGaps: CHROME_MANIFEST_BASELINE.knownGaps,
    error:
      newPerms.length + newHosts.length === 0
        ? undefined
        : `manifest grants beyond the recorded A2 baseline: ${[...newPerms, ...newHosts].join(', ')}. ` +
          'If this widening is intended, justify it and update CHROME_MANIFEST_BASELINE.',
  };
}

// ── Production dependency allowlist ──────────────────────────────────────────
//
// The AST scan covers the code we wrote and the code esbuild inlined. It does
// NOT cover a runtime dependency that the CLI resolves from node_modules at
// install time — `npm i` on a user's machine pulls that fresh. So the shipped
// production dependency closure is itself part of the A2 claim, and the honest
// way to hold it is to require it to stay inside our own scope.
const PROD_DEP_ALLOWLIST = [/^@vibeguard\//];

function checkProdDeps() {
  const workspaces = ['@vibeguard/cli'];
  const results = [];
  for (const ws of workspaces) {
    let raw;
    try {
      // `shell: true` is required on Windows: since Node 20 the child_process
      // family refuses to execute a .cmd shim directly (EINVAL), and npm on
      // Windows is exactly that. The argv is fully literal — no interpolation
      // of anything caller-controlled — so the shell adds no injection surface.
      raw = execFileSync(
        process.platform === 'win32' ? 'npm.cmd' : 'npm',
        ['ls', '--omit=dev', '--all', '--json', '--workspace', ws],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          maxBuffer: 32 * 1024 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'],
          shell: process.platform === 'win32',
        },
      );
    } catch (err) {
      // `npm ls` exits non-zero on any peer/extraneous complaint while still
      // emitting usable JSON on stdout. Only a genuinely empty stdout is fatal.
      raw = err.stdout;
      if (!raw) return { ok: false, error: `npm ls failed for ${ws}: ${err.message}` };
    }
    const tree = JSON.parse(raw);

    // `npm ls --workspace X` reports the whole installed tree with X nested
    // under the root's dependencies, and it lists root-level siblings that no
    // manifest requires (marked `extraneous`). On a CI runner after `npm ci`
    // there are none; on a developer machine there are, because
    // scripts/sec-a1-rewrite-check.mjs installs `recheck` with
    // `npm install --no-save`. Descending from the workspace node instead of
    // from the root is what makes the answer the same in both places — and it
    // cannot hide a real dependency, since anything declared in a package.json
    // is by definition reachable from the workspace node and never extraneous.
    const wsNode = tree.dependencies?.[ws];
    if (!wsNode) return { ok: false, error: `npm ls did not report a node for workspace ${ws}` };

    const names = new Set();
    const walk = (node) => {
      for (const [name, child] of Object.entries(node.dependencies ?? {})) {
        if (child.extraneous) continue;
        if (names.has(name)) continue;
        names.add(name);
        walk(child);
      }
    };
    walk(wsNode);

    const extraneous = Object.entries(tree.dependencies ?? {})
      .filter(([, v]) => v.extraneous)
      .map(([k]) => k)
      .sort();

    const offenders = [...names].sort().filter((n) => !PROD_DEP_ALLOWLIST.some((re) => re.test(n)));
    results.push({ workspace: ws, deps: [...names].sort(), offenders, ignoredExtraneous: extraneous });
  }
  const bad = results.filter((r) => r.offenders.length > 0);
  return {
    ok: bad.length === 0,
    results,
    error:
      bad.length === 0
        ? undefined
        : `production dependencies outside the allowlist: ${bad
            .map((r) => `${r.workspace} → ${r.offenders.join(', ')}`)
            .join('; ')}. Every third-party runtime dependency is un-audited egress surface.`,
  };
}

// ── Closure completeness ─────────────────────────────────────────────────────
//
// The structural guard against "we never looked there" (vacuous-pass path 4).
//
// PROD_DEP_ALLOWLIST accepts a dependency on the strength of its NAME. That is
// a reasonable rule — we do control everything under @vibeguard/ — but taken
// alone it is a trust assertion, not a verification: `npm ls` reports names,
// and a name says nothing about whether the package calls fetch(). Between the
// name-based allowlist and the AST scan there was a gap wide enough to drive
// the entire analyzer through, and it was open: appending an outbound fetch to
// packages/analyzer-core/dist/index.js left `--mode dist` reporting PASS,
// because @vibeguard/analyzer-core was allowlisted by name and scanned by
// nobody.
//
// The fix is to refuse to let those two facts be established independently.
// Every package the allowlist waves through must ALSO be a directory some
// target opened and parsed, and this check fails if it is not. The property it
// buys is the one that survives future contributors: when a sixth workspace
// package is added, `npm ls` reports it, the name matches `@vibeguard/`, the
// allowlist accepts it — and CI goes red until it is added to targets(). The
// only way to obtain a green run is to have actually read the code.
//
// The check is deliberately one-directional. A target with no packageName
// (vscode, chrome) is fine — those are shipped artefacts, not dependencies.
// What is not fine is a dependency with no target.
function checkClosureCompleteness(opts, depsResult, distResults) {
  const allTargets = targets(opts);
  const scannedPackages = new Map(
    allTargets.filter((t) => t.packageName).map((t) => [t.packageName, t]),
  );

  // A target that failed to scan (missing dir, below its file floor) does not
  // count as covering its package. Otherwise a deleted dist would satisfy this
  // check while satisfying nothing else, which is the same silent-zero bug in
  // a new costume.
  const scanOutcome = new Map((distResults ?? []).map((r) => [r.id, r]));

  const uncovered = [];
  for (const r of depsResult.results ?? []) {
    const closure = [r.workspace, ...(r.deps ?? [])];
    for (const name of closure) {
      if (!PROD_DEP_ALLOWLIST.some((re) => re.test(name))) continue; // offenders are r.offenders' business
      const t = scannedPackages.get(name);
      if (!t) {
        uncovered.push({
          package: name,
          reason: 'allowlisted by name but no scan target covers it — add it to targets()',
        });
        continue;
      }
      const outcome = scanOutcome.get(t.id);
      if (outcome && !outcome.ok) {
        uncovered.push({
          package: name,
          reason: `scan target '${t.id}' did not complete successfully (${outcome.error ?? `${outcome.hits.length} sink(s)`}), so the package is not covered`,
        });
      }
    }
  }

  return {
    ok: uncovered.length === 0,
    scannedPackages: [...scannedPackages.keys()].sort(),
    uncovered,
    // Recorded so the report says whether the stronger form of this check ran.
    // Without a dist scan in the same invocation (`--mode deps` alone) we can
    // only assert that a target EXISTS for each package, not that it passed.
    verifiedAgainstDistScan: Boolean(distResults),
    error:
      uncovered.length === 0
        ? undefined
        : `production dependencies trusted by name but not covered by an AST scan: ${uncovered
            .map((u) => `${u.package} (${u.reason})`)
            .join('; ')}. The name-based allowlist is only sound while every name it accepts is also read.`,
  };
}

// ── Negative control ─────────────────────────────────────────────────────────
//
// The single most important part of this file. Every guard above reports
// "0 sinks" both when the distributables are clean and when the detector is
// broken. The control distinguishes the two: fixtures that each contain exactly
// one known sink, run through the SAME scanSource(), with a per-fixture
// assertion that the expected sink class came back. A regression that blinds
// the scanner turns this red on the very same CI run.
const CONTROL_DIR = resolve(REPO_ROOT, 'scripts/fixtures/a2-egress');

/** fixture basename → sink class it must produce. */
const CONTROL_EXPECTATIONS = {
  'seeded-fetch.js': 'net-call',
  'seeded-xhr.js': 'net-construct',
  'seeded-websocket.js': 'net-construct',
  'seeded-beacon.js': 'net-call',
  'seeded-node-https.js': 'node-net-import',
  'seeded-node-require-net.js': 'node-net-import',
  'seeded-image-exfil.js': 'net-construct',
  'seeded-script-inject.js': 'dom-element-create',
  'seeded-obfuscated.js': 'net-call',
  'decoy-rule-pattern.js': null, // must produce NO hit: this is the grep trap
  // Markup and stylesheet leg (A2-GAP-3). Each of these egresses with zero
  // JavaScript involved, which is precisely why the JS-only scanner could
  // report a clean zero for the Chrome side panel.
  'seeded-html-script-src.html': 'html-remote-ref',
  'seeded-html-img-pixel.html': 'html-remote-ref',
  'seeded-html-preconnect.html': 'html-remote-ref',
  'seeded-html-inline-script.html': 'net-call', // inline <script> goes through the AST, not the regex
  'seeded-css-url.css': 'css-remote-ref',
  'seeded-css-import.css': 'css-import',
  // Three ways the markup leg was still blind after the first HTML/CSS pass.
  // All were found by adversarial review on 2026-07-20, all scanned clean before
  // the fix, and each one egresses with no JavaScript at all.
  'seeded-html-entity-scheme.html': 'html-remote-ref', // &#104;ttps:// — scheme broken for the audit, not the browser
  'seeded-html-svg-xlink.html': 'html-remote-ref', // inline SVG fetches via xlink:href, not src
  'seeded-html-base-href.html': 'html-remote-ref', // rewrites every relative URL to a remote origin
  'decoy-local-refs.html': null, // relative paths + data: URI only — must stay silent
  'decoy-local-assets.css': null, // same, for url()/@import
};

function runControl() {
  if (!existsSync(CONTROL_DIR)) {
    return { ok: false, error: `control fixtures missing at ${CONTROL_DIR}` };
  }
  // Every fixture extension the real targets can contain, so a fixture whose
  // scanner leg is broken cannot hide by being an extension the control forgot
  // to enumerate.
  const present = readdirSync(CONTROL_DIR).filter((f) => /\.(js|html?|css)$/i.test(f)).sort();
  const expected = Object.keys(CONTROL_EXPECTATIONS).sort();
  const missing = expected.filter((f) => !present.includes(f));
  const cases = [];

  for (const name of present) {
    const hits = scanFile(join(CONTROL_DIR, name), readFileSync(join(CONTROL_DIR, name), 'utf8'));
    const want = CONTROL_EXPECTATIONS[name];
    const sinks = hits.map((h) => h.sink);
    const pass =
      want === null
        ? hits.length === 0 // decoy: detector must NOT fire on rule-pattern strings
        : sinks.includes(want);
    cases.push({ fixture: name, expect: want ?? 'no-hit', got: sinks, pass });
  }

  const failed = cases.filter((c) => !c.pass);
  return {
    ok: failed.length === 0 && missing.length === 0,
    cases,
    missing,
    error:
      missing.length > 0
        ? `control fixtures absent: ${missing.join(', ')} — the negative control is incomplete, so a green dist scan proves nothing`
        : failed.length > 0
          ? `detector failed its own negative control: ${failed.map((c) => `${c.fixture} (wanted ${c.expect}, got [${c.got}])`).join('; ')}`
          : undefined,
  };
}

// ── Online/offline output comparison ─────────────────────────────────────────
//
// Used by the dynamic leg of the CI job: the CLI is run once normally and once
// with the network namespace removed, and the two reports must be identical.
// `findingId` is the one legitimately non-deterministic field (analyzer.ts:63
// derives it from the clock), so it is stripped — the same treatment
// consistency.test.ts already applies for the cross-channel comparison.
function compareReports(aPath, bPath) {
  const canon = (p) => {
    const doc = JSON.parse(readFileSync(p, 'utf8'));
    const findings = (doc.findings ?? []).map(({ findingId, ...rest }) => rest);
    findings.sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
    return JSON.stringify({ summary: doc.summary, findings }, null, 2);
  };
  const a = canon(aPath);
  const b = canon(bPath);
  return {
    ok: a === b,
    a: aPath,
    b: bPath,
    findings: JSON.parse(a).findings.length,
    error: a === b ? undefined : `online and offline reports differ (modulo findingId): ${aPath} vs ${bPath}`,
  };
}

// ── Driver ───────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = { mode: 'dist', quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--mode') opts.mode = argv[++i];
    else if (a === '--cli-dir') opts.cliDir = resolve(argv[++i]);
    else if (a === '--vscode-dir') opts.vscodeDir = resolve(argv[++i]);
    else if (a === '--chrome-dir') opts.chromeDir = resolve(argv[++i]);
    else if (a === '--out') opts.out = resolve(argv[++i]);
    else if (a === '--a') opts.a = argv[++i];
    else if (a === '--b') opts.b = argv[++i];
    else if (a === '--quiet') opts.quiet = true;
    else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return opts;
}

const opts = parseArgs(process.argv.slice(2));

if (opts.mode === 'compare') {
  if (!opts.a || !opts.b) {
    console.error('--mode compare requires --a <report.json> --b <report.json>');
    process.exit(2);
  }
  const r = compareReports(opts.a, opts.b);
  console.log(r.ok ? `A2 offline parity: OK (${r.findings} findings identical modulo findingId)` : `A2 offline parity: FAIL — ${r.error}`);
  process.exit(r.ok ? 0 : 1);
}

const report = { mode: opts.mode, node: process.version, checks: {} };

if (opts.mode === 'dist' || opts.mode === 'all') {
  report.checks.dist = targets(opts).map(scanTarget);
  report.checks.chromeManifest = checkChromeManifest(opts);
}
if (opts.mode === 'control' || opts.mode === 'all') {
  report.checks.control = runControl();
}
if (opts.mode === 'deps' || opts.mode === 'all') {
  report.checks.prodDeps = checkProdDeps();
  // Passed report.checks.dist when it exists (`--mode all`) so the check can
  // demand that the covering target actually PASSED, not merely that it was
  // declared. Under `--mode deps` alone it degrades to the existence check and
  // says so in the report.
  report.checks.closure = checkClosureCompleteness(opts, report.checks.prodDeps, report.checks.dist);
}
if (Object.keys(report.checks).length === 0) {
  console.error(`unknown --mode ${opts.mode} (dist | control | deps | compare | all)`);
  process.exit(2);
}

// Flatten every check into a single pass/fail list so the exit code cannot
// disagree with what was printed.
const failures = [];
const line = (s) => {
  if (!opts.quiet) console.log(s);
};

line('A2 — no-egress assertion');
line('');

if (report.checks.dist) {
  for (const t of report.checks.dist) {
    line(`  [${t.ok ? 'OK  ' : 'FAIL'}] ${t.id.padEnd(7)} ${String(t.files).padStart(3)} file(s) in ${t.dir}`);
    if (t.error) {
      line(`           ${t.error}`);
      failures.push(`dist/${t.id}: ${t.error}`);
    }
    for (const h of t.hits) {
      line(`           SINK ${h.sink} (${h.detail}) at ${h.file}:${h.line}`);
    }
    if (t.hits.length > 0) failures.push(`dist/${t.id}: ${t.hits.length} network sink(s)`);
  }
  const cm = report.checks.chromeManifest;
  line(`  [${cm.ok ? 'OK  ' : 'FAIL'}] manifest permissions=[${(cm.permissions ?? []).join(' ')}] host=[${(cm.hostPermissions ?? []).join(' ')}] csp=${cm.contentSecurityPolicy ?? 'default'}`);
  if (cm.error) failures.push(`chromeManifest: ${cm.error}`);
}

if (report.checks.control) {
  const c = report.checks.control;
  for (const k of c.cases ?? []) {
    line(`  [${k.pass ? 'OK  ' : 'FAIL'}] control ${k.fixture.padEnd(28)} expect ${k.expect} got [${k.got.join(',') || '-'}]`);
  }
  if (c.error) {
    line(`           ${c.error}`);
    failures.push(`control: ${c.error}`);
  }
}

if (report.checks.prodDeps) {
  const d = report.checks.prodDeps;
  for (const r of d.results ?? []) {
    line(`  [${r.offenders.length === 0 ? 'OK  ' : 'FAIL'}] prod-deps ${r.workspace}: ${r.deps.join(', ') || '(none)'}`);
    if (r.ignoredExtraneous?.length > 0) {
      line(`           (ignored ${r.ignoredExtraneous.length} extraneous, undeclared package(s): ${r.ignoredExtraneous.join(', ')})`);
    }
  }
  if (d.error) {
    line(`           ${d.error}`);
    failures.push(`prodDeps: ${d.error}`);
  }
}

if (report.checks.closure) {
  const c = report.checks.closure;
  line(
    `  [${c.ok ? 'OK  ' : 'FAIL'}] closure   ${c.scannedPackages.length} allowlisted package(s) AST-scanned: ${c.scannedPackages.join(', ')}` +
      (c.verifiedAgainstDistScan ? '' : ' (existence only — run --mode all to also require the scan passed)'),
  );
  if (c.error) {
    line(`           ${c.error}`);
    failures.push(`closure: ${c.error}`);
  }
}

// Printed unconditionally, in every mode, pass or fail. A green line above
// means "no sink was found in what was parsed"; these are the things that were
// not parsed. Reporting the first without the second is how an audit becomes a
// reassurance.
line('');
for (const g of KNOWN_GAPS) {
  line(`  KNOWN GAP ${g.id} [${g.scope}]: ${g.what}`);
  line(`             risk: ${g.risk}`);
}

report.knownGaps = KNOWN_GAPS;
report.ok = failures.length === 0;
report.failures = failures;

const outPath = opts.out ?? resolve(REPO_ROOT, 'security-experiment/_results/a2-egress-scan.json');
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');

line('');
line(
  report.ok
    ? 'A2: PASS — zero network sinks in the scanned execution closure: AST over JS/TS and over inline <script>/on* handlers, static remote-reference scan over HTML/CSS (see the known gaps above for what that sentence does not cover).'
    : `A2: FAIL — ${failures.length} problem(s).`,
);
line(`report: ${relative(REPO_ROOT, outPath).split(sep).join('/')}`);

process.exit(report.ok ? 0 : 1);
