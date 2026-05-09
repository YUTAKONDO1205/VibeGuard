// vibeguard:disable-file
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { describe, expect, it } from 'vitest';
import type { RuleContext, RuleDefinition } from '../rule-types.js';
import { evalUsage, sqlStringConcat, innerHtmlAssignment, dangerousDeserialization } from './injection.js';
import { dummyToken, tlsVerifyDisabled, debugBypass } from './auth.js';
import { hardcodedAwsKey, hardcodedPrivateKey, githubToken, genericApiKey } from './secrets.js';
import { weakHashForSecurity, weakRandomForSecurity, httpInsteadOfHttps } from './crypto.js';
import {
  exceptionSwallow,
  corsWildcardWithCredentials,
  debugLogOfSecret,
  openRedirect,
  stubBody,
  placeholderEmail,
  mockDataInProductionPath,
  debugFlagOn,
  notForProductionComment,
  emptyValidator,
} from './quality.js';

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

  it('captures innerHTML target as variable', () => {
    const matches = innerHtmlAssignment.match(ctx('container.innerHTML = data;'));
    expect(matches[0]?.variables?.target).toBe('container');
  });

  it('captures SQL table name as variable', () => {
    const matches = sqlStringConcat.match(
      ctx('const q = "SELECT * FROM users WHERE id = " + userId;'),
    );
    expect(matches[0]?.variables?.table).toBe('users');
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

describe('AI-heuristic rules (VG-QUAL-005..010)', () => {
  // VG-QUAL-005 — stub body
  it('flags throw new Error("Not implemented")', () => {
    expectMatches(stubBody, 'function deleteUser() { throw new Error("Not implemented"); }');
  });

  it('flags raise NotImplementedError', () => {
    expectMatches(stubBody, 'def authorize(user):\n    raise NotImplementedError');
  });

  it('flags Go panic("not implemented")', () => {
    expectMatches(stubBody, 'func Authorize() { panic("not implemented") }');
  });

  it('flags return null with TODO comment', () => {
    expectMatches(stubBody, 'function getUser(id) {\n    return null; // TODO implement\n}');
  });

  it('does not flag a real return null without TODO', () => {
    expectNoMatch(stubBody, 'function getUser(id) {\n    return null;\n}');
  });

  // VG-QUAL-006 — placeholder email
  it('flags noreply@example.com', () => {
    expectMatches(placeholderEmail, 'const FROM = "noreply@example.com";');
  });

  it('flags admin@test.com', () => {
    expectMatches(placeholderEmail, 'EMAIL = "admin@test.com"');
  });

  it('flags user@foo.bar', () => {
    expectMatches(placeholderEmail, 'to: "user@foo.bar"');
  });

  it('does not flag a normal email', () => {
    expectNoMatch(placeholderEmail, 'const FROM = "support@stripe.com";');
  });

  it('does not flag https://example.com URL (handled elsewhere)', () => {
    expectNoMatch(placeholderEmail, 'fetch("https://api.example.com/x")');
  });

  // VG-QUAL-007 — mock data outside test paths
  it('flags const mockUser =', () => {
    const matches = mockDataInProductionPath.match({
      content: 'const mockUser = { id: 1, name: "Alice" };',
      lines: ['const mockUser = { id: 1, name: "Alice" };'],
      filePath: 'src/handlers.ts',
    });
    expect(matches.length).toBe(1);
  });

  it('flags return mockUser', () => {
    const matches = mockDataInProductionPath.match({
      content: 'function getUser() { return mockUser; }',
      lines: ['function getUser() { return mockUser; }'],
      filePath: 'src/handlers.ts',
    });
    expect(matches.length).toBe(1);
  });

  it('flags python dummy_data = {}', () => {
    const matches = mockDataInProductionPath.match({
      content: 'dummy_data = {"id": 1}',
      lines: ['dummy_data = {"id": 1}'],
      filePath: 'src/app.py',
    });
    expect(matches.length).toBe(1);
  });

  it('does not flag mock data inside __tests__ path', () => {
    const matches = mockDataInProductionPath.match({
      content: 'const mockUser = { id: 1 };',
      lines: ['const mockUser = { id: 1 };'],
      filePath: 'src/__tests__/handlers.test.ts',
    });
    expect(matches.length).toBe(0);
  });

  it('does not flag mock data inside .test.ts file', () => {
    const matches = mockDataInProductionPath.match({
      content: 'const mockUser = { id: 1 };',
      lines: ['const mockUser = { id: 1 };'],
      filePath: 'src/handlers.test.ts',
    });
    expect(matches.length).toBe(0);
  });

  // VG-QUAL-008 — debug flag on
  it('flags debug: true in object literal', () => {
    expectMatches(debugFlagOn, 'export const config = { debug: true };');
  });

  it('flags verbose: true', () => {
    expectMatches(debugFlagOn, 'createLogger({ verbose: true });');
  });

  it('flags Python DEBUG = True', () => {
    expectMatches(debugFlagOn, 'DEBUG = True', 'python');
  });

  it('flags const DEBUG = true', () => {
    expectMatches(debugFlagOn, 'const DEBUG = true;');
  });

  it('does not flag debug: false', () => {
    expectNoMatch(debugFlagOn, 'export const config = { debug: false };');
  });

  it('does not flag debug: true inside a comment', () => {
    expectNoMatch(debugFlagOn, '// example: { debug: true }');
  });

  // VG-QUAL-009 — placeholder prose
  it('flags "// Not for production"', () => {
    expectMatches(notForProductionComment, 'const x = 1; // Not for production');
  });

  it('flags "// for now, just return the input"', () => {
    expectMatches(notForProductionComment, '// for now, return the input');
  });

  it('flags "// replace this with real validation"', () => {
    expectMatches(notForProductionComment, '// replace this with real validation later');
  });

  it('flags Python "# in production, you should validate"', () => {
    expectMatches(notForProductionComment, '# in production, you should validate');
  });

  it('does not flag the literal "production" alone', () => {
    expectNoMatch(notForProductionComment, '// production-ready impl');
  });

  // VG-QUAL-010 — empty validator
  it('flags function validate(x) { return true; }', () => {
    expectMatches(emptyValidator, 'function validate(input) { return true; }');
  });

  it('flags const sanitize = (x) => x;', () => {
    expectMatches(emptyValidator, 'const sanitize = (x) => x;');
  });

  it('flags python def validate(x): return True', () => {
    expectMatches(emptyValidator, 'def validate(x):\n    return True\n', 'python');
  });

  it('does not flag a real validator', () => {
    expectNoMatch(
      emptyValidator,
      'function validate(input) { if (!input) throw new Error("missing"); return input.trim(); }',
    );
  });
});
