// vibeguard:disable-file VG-SEC-001 VG-SEC-004 VG-AUTH-003
// This file's fixtures ARE secrets by construction — that is what it tests.
// The AWS key is Amazon's published example value and the GitHub token is an
// obvious fake; neither is a live credential. Rules named individually so the
// suppression cannot quietly widen.
import { describe, expect, it } from 'vitest';
import { maskSecret } from './snippet.js';
import { scan } from './index.js';

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
// Deliberately an obvious fake, matching the convention already used in
// `rules.test.ts`. A realistic-looking `ghp_` token in a committed file trips
// GitHub's own push protection and blocks the push — and a secrets test that
// cannot be pushed is worth less than one with a boring fixture.
const GH_TOKEN = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

/**
 * Redaction has to hold at the OUTPUT boundary, not just in one field.
 *
 * The regression these tests pin: `maskSecret` recognised a secret only when it
 * was written as a quoted string literal. Quoting is a property of the source
 * syntax, not of whether a value is a credential, so the same AWS key survived
 * verbatim whenever it appeared in a `.env`, a YAML value, or as a rule's bare
 * `evidence` — and `snippet` is the field the SARIF adapter emits, so a scan
 * uploaded to GitHub code scanning republished the key it had just found.
 */
describe('maskSecret', () => {
  it('masks a quoted literal', () => {
    expect(maskSecret(`const k = "${AWS_KEY}";`)).toBe('const k = "AKIA***";');
  });

  it('masks an unquoted YAML value', () => {
    expect(maskSecret(`  aws_access_key_id: ${AWS_KEY}`)).toBe('  aws_access_key_id: AKIA***');
  });

  it('masks an unquoted .env assignment', () => {
    expect(maskSecret(`AWS_ACCESS_KEY_ID=${AWS_KEY}`)).toBe('AWS_ACCESS_KEY_ID=AKIA***');
  });

  it('masks a bare token, the shape a rule evidence takes', () => {
    expect(maskSecret(AWS_KEY)).toBe('AKIA***');
  });

  it('leaves a known placeholder readable', () => {
    // VG-AUTH-003 exists to say "you used a known placeholder". Masking it to
    // `chan***` would delete the finding's entire message, and there is nothing
    // to protect: the value is worthless precisely because it is public.
    expect(maskSecret('"changeme"')).toBe('"changeme"');
    expect(maskSecret('"letmein"')).toBe('"letmein"');
  });

  // Length is not what separates a credential from a placeholder. Keying on it
  // walked straight past every real password: `Tsu9any0!` is nine characters
  // with punctuation, which is what a password policy asks for.
  it('masks a short real password', () => {
    expect(maskSecret('WiFi.begin("HomeNet", "Tsu9any0!")')).toContain('Tsu9***');
    expect(maskSecret('WiFi.begin("HomeNet", "Tsu9any0!")')).not.toContain('Tsu9any0!');
    expect(maskSecret('#define OTA_PASSWORD "Tsu9any0!"')).not.toContain('Tsu9any0!');
  });

  it('does not collapse a key name when re-masking an already-masked value', () => {
    // `*` is a legitimate password character, so a masked value still looks
    // secret-shaped. Without an explicit guard `KEY=AKIA***` was re-matched as
    // one bare token and became `AWS_***`.
    const once = maskSecret('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
    expect(once).toBe('AWS_ACCESS_KEY_ID=AKIA***');
    expect(maskSecret(once)).toBe(once);
  });

  it('does not mangle a URL authority', () => {
    const url = 'https://api.longhostname.example.com/v1';
    expect(maskSecret(url)).toBe(url);
  });

  it('is idempotent', () => {
    const once = maskSecret(`key: ${AWS_KEY}`);
    expect(maskSecret(once)).toBe(once);
  });

  it('throws on a non-string, so analyzer.ts can record it as a rule error', () => {
    expect(() => maskSecret(null as unknown as string)).toThrow();
  });
});

describe('secrets never reach a finding in plaintext', () => {
  const scanText = (content: string, filePath: string): ReturnType<typeof scan> =>
    scan({ targetType: 'file', content, filePath, mode: 'standard' });

  it('redacts an unquoted YAML secret in both snippet and evidence', () => {
    const r = scanText(`stringData:\n  aws_access_key_id: ${AWS_KEY}\n`, 'k8s-secret.yml');
    const secrets = r.findings.filter((f) => f.category === 'secrets');
    expect(secrets.length).toBeGreaterThan(0);
    for (const f of secrets) {
      expect(f.snippet ?? '').not.toContain(AWS_KEY);
      for (const e of f.evidence ?? []) expect(e).not.toContain(AWS_KEY);
    }
  });

  // The path that makes this a disclosure bug rather than a cosmetic one: the
  // scanner has no `.gitignore` awareness (DEFAULT_IGNORE is a fixed set of
  // directory NAMES), so a `.env` materialised during CI from repository
  // secrets is scanned like any other file.
  it('redacts a CI-generated .env, which the scanner has no way to skip', () => {
    const r = scanText(`AWS_ACCESS_KEY_ID=${AWS_KEY}\nGITHUB_TOKEN=${GH_TOKEN}\n`, '.env');
    const serialised = JSON.stringify(r);
    expect(serialised).not.toContain(AWS_KEY);
    expect(serialised).not.toContain(GH_TOKEN);
  });

  it('redacts a quoted literal in source', () => {
    const r = scanText(`const AWS_ACCESS_KEY = "${AWS_KEY}";\n`, 'secrets.js');
    expect(JSON.stringify(r)).not.toContain(AWS_KEY);
  });

  // The embedded channel's credentials are short human-chosen passwords, not
  // long opaque tokens, so a length-based masker left every one of them intact.
  it('redacts a WiFi/OTA password from an Arduino sketch', () => {
    const sketch = [
      '#include <WiFi.h>',
      '#include <ArduinoOTA.h>',
      '',
      '#define OTA_PASSWORD "Tsu9any0!"',
      '',
      'void setup() {',
      '  Serial.begin(115200);',
      '  WiFi.begin("HomeNet", "Tsu9any0!");',
      '  ArduinoOTA.setPassword(OTA_PASSWORD);',
      '  ArduinoOTA.begin();',
      '}',
      '',
    ].join('\n');
    const r = scanText(sketch, 'sketch.ino');
    expect(r.findings.some((f) => f.category === 'secrets')).toBe(true);
    expect(JSON.stringify(r)).not.toContain('Tsu9any0!');
  });
});
