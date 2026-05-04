import { describe, expect, it } from 'vitest';
import type { RuleContext, RuleDefinition } from '../rule-types.js';
import { evalUsage, sqlStringConcat, innerHtmlAssignment, dangerousDeserialization } from './injection.js';
import { dummyToken, tlsVerifyDisabled, debugBypass } from './auth.js';
import { hardcodedAwsKey, hardcodedPrivateKey, githubToken, genericApiKey } from './secrets.js';
import { weakHashForSecurity, weakRandomForSecurity, httpInsteadOfHttps } from './crypto.js';
import { exceptionSwallow, corsWildcardWithCredentials, debugLogOfSecret, openRedirect } from './quality.js';

function ctx(content: string, language?: string): RuleContext {
  return { content, lines: content.split('\n'), language };
}

function expectMatches(rule: RuleDefinition, content: string, language?: string, count = 1) {
  const matches = rule.match(ctx(content, language));
  expect(matches.length).toBe(count);
  for (const m of matches) {
    expect(m.startLine).toBeGreaterThanOrEqual(1);
    expect(m.evidence.length).toBeGreaterThan(0);
  }
}

function expectNoMatch(rule: RuleDefinition, content: string, language?: string) {
  expect(rule.match(ctx(content, language))).toEqual([]);
}

describe('injection rules', () => {
  it('flags eval()', () => {
    expectMatches(evalUsage, 'const r = eval(userInput);');
  });

  it('does not flag method named eval', () => {
    expectNoMatch(evalUsage, 'obj.eval(123);');
  });

  it('does not flag eval inside a comment', () => {
    expectNoMatch(evalUsage, '// uses eval(input)');
  });

  it('flags SQL concatenation', () => {
    expectMatches(sqlStringConcat, 'const q = "SELECT * FROM users WHERE id = " + userId;');
  });

  it('flags innerHTML assignment with variable', () => {
    expectMatches(innerHtmlAssignment, 'el.innerHTML = userInput;');
  });

  it('does not flag innerHTML literal assignment', () => {
    expectNoMatch(innerHtmlAssignment, 'el.innerHTML = "<b>hello</b>";');
  });

  it('flags pickle.loads', () => {
    expectMatches(dangerousDeserialization, 'data = pickle.loads(blob)');
  });

  it('flags yaml.load without SafeLoader', () => {
    expectMatches(dangerousDeserialization, 'cfg = yaml.load(text)');
  });

  it('does not flag yaml.load with SafeLoader', () => {
    expectNoMatch(dangerousDeserialization, 'cfg = yaml.load(text, Loader=yaml.SafeLoader)');
  });
});

describe('auth rules', () => {
  it('flags placeholder credentials', () => {
    expectMatches(dummyToken, 'API_KEY = "changeme"');
  });

  it('flags TLS verify=False (python)', () => {
    expectMatches(tlsVerifyDisabled, 'requests.get(url, verify=False)');
  });

  it('flags rejectUnauthorized: false', () => {
    expectMatches(tlsVerifyDisabled, 'https.request({ rejectUnauthorized: false }, cb);');
  });

  it('flags debug bypass that returns true', () => {
    expectMatches(debugBypass, 'if (DEBUG) { return true; }');
  });
});

describe('secrets rules', () => {
  it('flags AWS access key', () => {
    expectMatches(hardcodedAwsKey, 'const k = "AKIAIOSFODNN7EXAMPLE";');
  });

  it('flags PEM private key block', () => {
    expectMatches(hardcodedPrivateKey, '-----BEGIN RSA PRIVATE KEY-----\nMIIEpQ...\n-----END RSA PRIVATE KEY-----');
  });

  it('flags GitHub PAT', () => {
    expectMatches(githubToken, 'token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"');
  });

  it('flags long literal assigned to api_key', () => {
    expectMatches(genericApiKey, 'const apiKey = "sk_live_AAAAAAAAAAAAAAAAAAAA";');
  });

  it('does not flag env var lookup', () => {
    expectNoMatch(genericApiKey, 'const apiKey = process.env.STRIPE_API_KEY;');
  });

  it('does not flag known placeholder (handed off to VG-AUTH-003)', () => {
    expectNoMatch(genericApiKey, 'const apiKey = "your_api_key_here_xxxxxxxxxxx";');
  });
});

describe('crypto rules', () => {
  it('flags hashlib.md5', () => {
    expectMatches(weakHashForSecurity, 'h = hashlib.md5(p).hexdigest()');
  });

  it('flags Math.random for token', () => {
    expectMatches(weakRandomForSecurity, 'const sessionId = Math.random().toString(36);');
  });

  it('does not flag Math.random for non-security use', () => {
    expectNoMatch(weakRandomForSecurity, 'const x = Math.random();');
  });

  it('flags non-localhost http://', () => {
    expectMatches(httpInsteadOfHttps, 'fetch("http://api.example.com/login")');
  });

  it('does not flag http://localhost', () => {
    expectNoMatch(httpInsteadOfHttps, 'fetch("http://localhost:3000/login")');
  });
});

describe('quality rules', () => {
  it('flags except: pass', () => {
    expectMatches(exceptionSwallow, 'try:\n    do()\nexcept Exception:\n    pass');
  });

  it('flags empty catch block', () => {
    expectMatches(exceptionSwallow, 'try { run(); } catch (e) {}');
  });

  it('flags CORS wildcard with credentials', () => {
    expectMatches(
      corsWildcardWithCredentials,
      'res.setHeader("Access-Control-Allow-Origin", "*");\nres.setHeader("Access-Control-Allow-Credentials", "true");',
    );
  });

  it('flags console.log of password', () => {
    expectMatches(debugLogOfSecret, 'console.log("login attempt", password);');
  });

  it('flags open redirect from req.query', () => {
    expectMatches(openRedirect, 'res.redirect(req.query.next)');
  });
});
