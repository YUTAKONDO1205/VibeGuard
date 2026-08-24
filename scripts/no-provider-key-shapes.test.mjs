// No tracked file may carry a string a secret scanner will treat as a
// credential.
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//
// A scanner for AI-generated code needs fixtures that look like credentials,
// and a fixture that looks like a credential is what a secret scanner is built
// to find. The first attempt at managing that was a judgement call per
// provider: two formats were assembled at run time because GitHub's PUSH
// PROTECTION had refused them, and the rest were written out literally on the
// strength of having got past it.
//
// That reasoning was wrong twice. Push protection blocks a SUBSET of what
// secret scanning alerts on, so clearing the gate says nothing about the alert;
// and a scanner's coverage grows, so a format that is quiet today is not quiet
// tomorrow. GitHub opened a "publicly leaked secret" alert on an invented
// Google key within minutes of the push that introduced it — and being invented
// is exactly what a scanner cannot know and should not have to guess.
//
// Where a rule must be tested against a real-looking key, the literal is
// assembled at run time (see the top of `packages/rules/src/rules/rules.test.ts`).
// The rule under test sees the joined string exactly as it would see it in a
// file, and no file contains it.
//
// ── WHY IT SCANS TRACKED FILES ──────────────────────────────────────────────
//
// What matters is what leaves the machine. `git ls-files` is what a push
// carries; an untracked scratch fixture is nobody's problem, and including one
// would only make this noisy enough to be switched off.

import { expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The formats, and the floor this list may never fall below.
 *
 * ── IT MUST NOT BE NARROWER THAN THE PRODUCT'S OWN RULES ────────────────────
 *
 * The first version claimed to be "slightly WIDER than the corresponding
 * VG-SEC-005 patterns on purpose". It was not. Measured against random
 * base64url bodies, `sk-ant-[A-Za-z0-9-]{20,}` missed 21.9% of real-shaped
 * Anthropic keys, because a real one is base64url and base64url contains `_`,
 * which that character class omits — while `packages/rules/src/rules/secrets.ts`
 * catches the same string. A hygiene gate narrower than the scanner it is meant
 * to keep clean is worse than none: it reports green over exactly the strings
 * the product would flag.
 *
 * Two formats were also missing outright that the product itself detects:
 * `github_pat_` (VG-SEC-004) and a PEM private key block (VG-SEC-002).
 *
 * So the rule for this list: every shape any VibeGuard rule recognises appears
 * here, at least as wide, plus the partner formats a fixture is likely to reach
 * for. It is still not all 200-plus patterns GitHub scans — that is not
 * achievable here and the gap is stated rather than implied.
 */
const SHAPES = [
  ['OpenAI project key', /sk-proj-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI service/admin key', /sk-(?:svcacct|admin)-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI user key', /sk-[A-Za-z0-9]{32,}/g],
  ['Anthropic key', /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ['OpenRouter key', /sk-or-v1-[A-Za-z0-9]{32,}/g],
  ['Google API key', /AIza[A-Za-z0-9_-]{35}/g],
  ['Google OAuth client secret', /GOCSPX-[A-Za-z0-9_-]{20,}/g],
  ['Hugging Face token', /hf_[A-Za-z0-9]{30,}/g],
  ['Groq key', /gsk_[A-Za-z0-9]{30,}/g],
  ['Stripe key', /[rs]k_(?:live|test)_[A-Za-z0-9]{20,}/g],
  ['AWS access key id', /(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])/g],
  ['GitHub token', /(?:ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9]{36}/g],
  ['GitHub fine-grained PAT', /github_pat_[A-Za-z0-9_]{40,}/g],
  ['GitLab PAT', /glpat-[A-Za-z0-9_-]{20,}/g],
  ['Slack token', /xox[baprs]-[A-Za-z0-9-]{20,}/g],
  ['npm token', /npm_[A-Za-z0-9]{30,}/g],
  ['PyPI token', /pypi-[A-Za-z0-9_-]{40,}/g],
  ['SendGrid key', /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g],
  ['Shopify token', /shpat_[a-fA-F0-9]{32}/g],
  ['Azure storage account key', /AccountKey=[A-Za-z0-9+/=]{60,}/g],
  // The HEADER alone is not a credential — `packages/rules/src/rules/secrets.ts`
  // flags it as VG-SEC-002 because a header in source is a smell, but a scanner
  // needs key MATERIAL to call it a leak, and the fixture for that rule carries
  // only the header. So this requires at least one line of base64 after it.
  ['PEM private key with material', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=]{40,}/g],
];

/**
 * Whether a matched string is obviously not a credential.
 *
 * ── WHY A PREDICATE AND NOT A LIST OF ALLOWED STRINGS ───────────────────────
 *
 * The first version of this file declared the rule absolute and allowlisted two
 * strings by hand. Running it over the tree immediately produced thirteen more
 * — `AKIA` followed by sixteen `A`s in a canonicaliser test, `sk_live_AAAA…` in
 * the secrets corpus, `ghp_abcdefgh…` in test_problem — every one a long-standing
 * fixture that no scanner has ever alerted on. An absolute rule its own
 * repository breaks thirteen times is not a rule; it is a thing somebody
 * deletes.
 *
 * So this encodes the test the scanners actually apply. They do not alert on a
 * shape, they alert on a shape whose BODY could plausibly be a key. A body of
 * one repeated character, or the alphabet in order, or the word EXAMPLE, is
 * rejected by the provider's own validator and by every entropy filter — which
 * is exactly why those thirteen have sat there unremarked.
 *
 * The Google key that caused a real alert had a body of mixed-case letters and
 * digits with no repetition. That is the line this draws, and it is the line
 * that decides whether a push becomes an incident.
 */
export function looksSynthetic(match) {
  const body = match.replace(
    /^(?:sk-proj-|sk-ant-|sk-|AIza|hf_|gsk_|[rs]k_live_|AKIA|ASIA|gh[porsu]_)/,
    '',
  );
  if (body.length < 8) return true;
  if (/EXAMPLE|SAMPLE|PLACEHOLDER|NOTAREAL|YOURKEY|YOUR-KEY|XXXX/i.test(body)) return true;
  // Too few distinct characters to carry a key's entropy.
  if (new Set(body.toLowerCase()).size <= 6) return true;
  // The alphabet or the digits in order, either direction.
  const ordered = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const lower = body.toLowerCase();
  if (ordered.includes(lower) || [...ordered].reverse().join('').includes(lower)) return true;
  // One short run repeated: abcabcabc… Up to twelve, because the existing
  // `ghp_` fixture in test_problem is `abcdefghij` four times over and a
  // six-character ceiling missed it — a real key's body has no period at all,
  // so the bound only has to be longer than the runs people actually type.
  for (let n = 1; n <= 12; n += 1) {
    const rep = body.slice(0, n).repeat(Math.ceil(body.length / n)).slice(0, body.length);
    if (body.length > n && body === rep) return true;
  }
  return false;
}

/** This file names every shape it forbids, which is unavoidable. */
const SELF = 'scripts/no-provider-key-shapes.test.mjs';

const SKIP_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.woff', '.woff2', '.zip', '.docx',
]);
const MAX_BYTES = 2_000_000;

it('no tracked file carries a plausible provider key', () => {
  const listed = execFileSync('git', ['ls-files', '-z'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split('\0')
    .filter(Boolean);

  // Vacuity guard. A `git ls-files` that returned nothing — wrong directory,
  // not a checkout — would make this pass over an empty set, which is the shape
  // of failure this whole area keeps producing.
  expect(listed.length, 'git ls-files did not scan the tree').toBeGreaterThan(500);

  const offenders = [];
  let scanned = 0;
  for (const rel of listed) {
    if (rel === SELF) continue;
    const dot = rel.lastIndexOf('.');
    if (dot !== -1 && SKIP_EXT.has(rel.slice(dot).toLowerCase())) continue;
    const abs = join(REPO_ROOT, rel);
    let text;
    try {
      if (statSync(abs).size > MAX_BYTES) continue;
      text = readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    scanned += 1;
    for (const [name, re] of SHAPES) {
      for (const m of text.match(re) ?? []) {
        if (looksSynthetic(m)) continue;
        offenders.push(`${rel}: ${name} — ${m.slice(0, 12)}…`);
      }
    }
  }

  expect(scanned, 'the walk is not covering the tree').toBeGreaterThan(400);
  expect(
    offenders,
    'a tracked file contains a plausible provider key. Assemble it at run time instead — ' +
      'see the note at the top of packages/rules/src/rules/rules.test.ts',
  ).toEqual([]);
});

it('the predicate admits the obviously fake and refuses the plausible', () => {
  // The last assertion is the one that matters: that string is exactly what
  // GitHub opened a "publicly leaked secret" alert on.
  //
  // The line below is the one place in this file that has to spell an AWS key
  // out — the predicate cannot be tested against a shape it is never handed —
  // so VG-SEC-001 finds it and the self-scan's `--fail-on critical` goes red on
  // it. Suppressed at LINE scope rather than file scope on purpose: file scope
  // would also cover anything a later edit adds, and this file's whole subject
  // is that a credential-shaped string in a tracked file is an event.
  // vibeguard:disable-next-line VG-SEC-001
  expect(looksSynthetic('AKIAIOSFODNN7EXAMPLE')).toBe(true);
  expect(looksSynthetic(`sk_live_${'A'.repeat(24)}`)).toBe(true);
  expect(looksSynthetic(`ghp_${'abcdefghij'.repeat(4).slice(0, 36)}`)).toBe(true);
  expect(looksSynthetic(`gsk_${'0'.repeat(40)}notarealkey`)).toBe(true);
  expect(looksSynthetic(`AI${'za'}SyB4nR8kQw3rTy6UiOp0aSdFgHjKlZxCvBn`)).toBe(false);
  expect(looksSynthetic(['sk', 'proj', 'Zt7QreamLbXk20fV8pMwNc41hYuEsD9g'].join('-'))).toBe(false);
});
