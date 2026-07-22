// vibeguard:disable-file VG-CRYPTO-003 VG-AUTH-001 VG-AUTH-003 VG-AUTH-004 VG-AUTH-006 VG-CRYPTO-001 VG-CRYPTO-002 VG-FW-003 VG-INJ-001 VG-INJ-004 VG-INJ-006 VG-INJ-020 VG-QUAL-001 VG-QUAL-002 VG-QUAL-003 VG-QUAL-004 VG-QUAL-005 VG-QUAL-006 VG-QUAL-008 VG-QUAL-009 VG-QUAL-010 VG-SEC-001 VG-SEC-002 VG-SEC-003 VG-SEC-004 VG-SMELL-003 VG-SMELL-004 VG-SMELL-012 VG-AISC-001
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { describe, expect, it } from 'vitest';
import type { RuleContext, RuleDefinition } from '../rule-types.js';
import { evalUsage, sqlStringConcat, innerHtmlAssignment, dangerousDeserialization, prototypePollutingMerge } from './injection.js';
import { longSecurityMethod, primitiveRoleCheck, securitySwissArmyKnife } from './design-smells-single.js';
import { hallucinatedDependency } from './ai-supply-chain.js';
import {
  dummyToken,
  tlsVerifyDisabled,
  debugBypass,
  csrfExemptDecorator,
  insecureSessionCookie,
} from './auth.js';
import { djangoDebugTrue, flaskDebugRun, corsWildcardOrigin } from './framework.js';
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
import { goSqlSprintf, goTemplateHtmlCast, goListenAllInterfacesHttp } from './lang-go.js';
import { javaRuntimeExecConcat, javaXxeDocumentBuilder, javaObjectInputStream } from './lang-java.js';
import {
  rubyRailsRawOrHtmlSafe,
  rubyEvalFamily,
  rubyParamsPermitBang,
  railsCsrfDisabled,
} from './lang-ruby.js';
import {
  phpExtractRequest,
  phpDynamicInclude,
  phpUnserialize,
  phpLegacyMysqlConcat,
} from './lang-php.js';

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

  // `//` opens a comment in JavaScript, so the language must be passed: comment
  // syntax is per-language now, and an absent language means nothing is a
  // comment (fail-safe — see LINE_COMMENT_SPECS).
  it('does not flag eval inside a comment', () => {
    expectNoMatch(evalUsage, '// uses eval(input)', 'javascript');
  });

  // Regression: `#` opens an ES2022 private class field, not a comment. Without
  // a language the comment-line predicate reads these as comments and
  // runRegex({ skipCommentLines }) DROPS the match — a silent false negative
  // upstream of the analyzer's confidence chokepoint, so no severity gate can
  // catch it.
  it('flags eval() on an ES2022 private field line', () => {
    expectMatches(evalUsage, 'class C {\n  #q = (s) => eval(s);\n}', 'javascript');
  });

  it('flags SQL concatenation on an ES2022 private field line', () => {
    expectMatches(
      sqlStringConcat,
      'class C {\n  #x = "SELECT * FROM users WHERE id = " + id;\n}',
      'javascript',
    );
  });

  // The other direction: where `#` really is a comment, it must stay skipped.
  it('does not flag eval inside a Python # comment', () => {
    expectNoMatch(evalUsage, '# eval(x)', 'python');
  });

  it('does not flag SQL concatenation inside a Python # comment', () => {
    expectNoMatch(sqlStringConcat, '# q = "SELECT * FROM users WHERE id = " + id', 'python');
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

  it('flags rejectUnauthorized: false on an ES2022 private field line', () => {
    expectMatches(
      tlsVerifyDisabled,
      'class C {\n  #a = { rejectUnauthorized: false };\n}',
      'javascript',
    );
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

  it('flags Ruby Digest::MD5.hexdigest', () => {
    expectMatches(weakHashForSecurity, "fingerprint = Digest::MD5.hexdigest(payload)", 'ruby');
  });

  it('flags C# MD5.Create()', () => {
    expectMatches(weakHashForSecurity, 'using var hasher = MD5.Create();', 'csharp');
  });

  it('flags PHP md5() top-level call', () => {
    expectMatches(weakHashForSecurity, '$hash = md5($password);', 'php');
  });

  it('does not double-flag hashlib.md5 via the bare-md5 pattern', () => {
    // hashlib.md5( should be flagged exactly once (by the Python regex),
    // not also by the bare md5( regex (the negative lookbehind blocks it).
    expectMatches(weakHashForSecurity, 'h = hashlib.md5(p).hexdigest()', 'python', 1);
  });

  it('flags Math.random for token', () => {
    expectMatches(weakRandomForSecurity, 'const sessionId = Math.random().toString(36);');
  });

  it('flags Java new Random() for token', () => {
    expectMatches(weakRandomForSecurity, 'int token = new Random().nextInt();', 'java');
  });

  it('flags Go math/rand for session id', () => {
    expectMatches(weakRandomForSecurity, 'sessionId := rand.Intn(1000000)', 'go');
  });

  it('flags PHP mt_rand for token', () => {
    expectMatches(weakRandomForSecurity, '$token = mt_rand(0, 999999);', 'php');
  });

  it('flags Ruby Kernel#rand for nonce', () => {
    expectMatches(weakRandomForSecurity, 'nonce = rand(2 ** 64)', 'ruby');
  });

  it('flags C# new Random() for password', () => {
    expectMatches(
      weakRandomForSecurity,
      'var password = new Random().Next().ToString();',
      'csharp',
    );
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

  it('does not flag raise NotImplementedError inside an @abstractmethod (idiomatic abstract contract)', () => {
    expectNoMatch(
      stubBody,
      'import abc\n\nclass Gateway(abc.ABC):\n    @abc.abstractmethod\n    def charge(self, amount):\n        raise NotImplementedError',
    );
    expectNoMatch(
      stubBody,
      'from abc import abstractmethod\n\nclass Repo:\n    @abstractmethod\n    def save(self, x):\n        raise NotImplementedError',
    );
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
    expectNoMatch(debugFlagOn, '// example: { debug: true }', 'javascript');
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

describe('framework rules', () => {
  // VG-AUTH-005 — Django @csrf_exempt
  it('flags @csrf_exempt at start of line', () => {
    expectMatches(csrfExemptDecorator, '@csrf_exempt\ndef view(request):\n    pass\n', 'python');
  });

  it('flags indented @csrf_exempt (class method)', () => {
    expectMatches(csrfExemptDecorator, '    @csrf_exempt\n    def post(self, request):\n        pass\n', 'python');
  });

  it('does not flag @csrf_exempt inside a string literal', () => {
    expectNoMatch(csrfExemptDecorator, 'doc = "uses @csrf_exempt for testing"', 'python');
  });

  // VG-AUTH-006 — express-session insecure cookie flags
  it('flags cookie secure: false', () => {
    expectMatches(insecureSessionCookie, 'session({ cookie: { secure: false, httpOnly: true } })');
  });

  it('flags httpOnly: false', () => {
    expectMatches(insecureSessionCookie, 'session({ cookie: { secure: true, httpOnly: false } })');
  });

  it('does not flag secure: true', () => {
    expectNoMatch(insecureSessionCookie, 'session({ cookie: { secure: true, httpOnly: true } })');
  });

  // VG-FW-001 — Django DEBUG = True
  it('flags DEBUG = True at module level', () => {
    expectMatches(djangoDebugTrue, 'DEBUG = True\nALLOWED_HOSTS = []\n', 'python');
  });

  it('does not flag DEBUG = False', () => {
    expectNoMatch(djangoDebugTrue, 'DEBUG = False\n', 'python');
  });

  it('does not flag DEBUG = os.environ.get(...)', () => {
    expectNoMatch(djangoDebugTrue, 'DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"\n', 'python');
  });

  // VG-FW-002 — Flask app.run(debug=True)
  it('flags app.run(debug=True)', () => {
    expectMatches(flaskDebugRun, 'app.run(debug=True)', 'python');
  });

  it('flags app.run(host="0.0.0.0", debug=True)', () => {
    expectMatches(flaskDebugRun, 'app.run(host="0.0.0.0", debug=True)', 'python');
  });

  it('does not flag app.run() without debug', () => {
    expectNoMatch(flaskDebugRun, 'app.run(host="127.0.0.1")', 'python');
  });

  // VG-FW-003 — CORS wildcard origin
  it("flags cors({ origin: '*' })", () => {
    expectMatches(corsWildcardOrigin, "app.use(cors({ origin: '*' }));");
  });

  it('flags Access-Control-Allow-Origin: * header literal', () => {
    expectMatches(
      corsWildcardOrigin,
      'res.setHeader("Access-Control-Allow-Origin", "*");',
    );
  });

  it("flags Flask-CORS origins: '*'", () => {
    expectMatches(corsWildcardOrigin, "CORS(app, resources={r'/*': {'origins': '*'}})", 'python');
  });

  it('does not flag explicit origin list', () => {
    expectNoMatch(
      corsWildcardOrigin,
      "app.use(cors({ origin: ['https://app.example.com'] }));",
    );
  });
});

describe('Go language pack', () => {
  it('flags fmt.Sprintf with SELECT', () => {
    expectMatches(
      goSqlSprintf,
      'q := fmt.Sprintf("SELECT * FROM users WHERE id = %d", userID)',
      'go',
    );
  });

  it('does not flag fmt.Sprintf for a non-SQL string', () => {
    expectNoMatch(goSqlSprintf, 'msg := fmt.Sprintf("hello %s", name)', 'go');
  });

  it('flags template.HTML cast on a variable', () => {
    expectMatches(goTemplateHtmlCast, 'safe := template.HTML(userBio)', 'go');
  });

  it('does not flag template.HTML cast on a string literal', () => {
    expectNoMatch(goTemplateHtmlCast, 'safe := template.HTML("<b>ok</b>")', 'go');
  });

  it('flags http.ListenAndServe on all interfaces', () => {
    expectMatches(goListenAllInterfacesHttp, 'http.ListenAndServe(":8080", mux)', 'go');
  });

  it('does not flag http.ListenAndServeTLS', () => {
    expectNoMatch(
      goListenAllInterfacesHttp,
      'http.ListenAndServeTLS(":443", certFile, keyFile, mux)',
      'go',
    );
  });
});

describe('Java language pack', () => {
  it('flags Runtime.getRuntime().exec with concatenation', () => {
    expectMatches(
      javaRuntimeExecConcat,
      'Runtime.getRuntime().exec("ping " + host);',
      'java',
    );
  });

  it('flags new ProcessBuilder with concatenation', () => {
    expectMatches(
      javaRuntimeExecConcat,
      'new ProcessBuilder("sh", "-c", "ls " + dir).start();',
      'java',
    );
  });

  it('does not flag Runtime.exec with a String[]', () => {
    expectNoMatch(
      javaRuntimeExecConcat,
      'Runtime.getRuntime().exec(new String[]{"ping", host});',
      'java',
    );
  });

  it('flags DocumentBuilderFactory.newInstance()', () => {
    expectMatches(
      javaXxeDocumentBuilder,
      'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();',
      'java',
    );
  });

  it('flags ObjectInputStream construction', () => {
    expectMatches(
      javaObjectInputStream,
      'ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());',
      'java',
    );
  });

  it('flags .readObject() invocation', () => {
    expectMatches(javaObjectInputStream, 'Object o = ois.readObject();', 'java');
  });
});

describe('Ruby/Rails language pack', () => {
  it('flags raw(@user.bio)', () => {
    expectMatches(rubyRailsRawOrHtmlSafe, '<%= raw(@user.bio) %>', 'ruby');
  });

  it('flags @user.bio.html_safe', () => {
    expectMatches(rubyRailsRawOrHtmlSafe, '<%= @user.bio.html_safe %>', 'ruby');
  });

  it('does not flag raw("<b>ok</b>")', () => {
    expectNoMatch(rubyRailsRawOrHtmlSafe, '<%= raw("<b>ok</b>") %>', 'ruby');
  });

  it('flags eval(user_code)', () => {
    expectMatches(rubyEvalFamily, 'eval(user_code)', 'ruby');
  });

  it('flags obj.instance_eval(code)', () => {
    expectMatches(rubyEvalFamily, 'thing.instance_eval(code)', 'ruby');
  });

  it('does not flag eval("1 + 1") literal', () => {
    expectNoMatch(rubyEvalFamily, 'eval("1 + 1")', 'ruby');
  });

  it('does not flag eval inside a Ruby # comment', () => {
    expectNoMatch(rubyEvalFamily, '# eval(user_code)', 'ruby');
  });

  it('flags params.permit!', () => {
    expectMatches(rubyParamsPermitBang, 'user = User.new(params.permit!)', 'ruby');
  });

  it('flags skip_before_action :verify_authenticity_token', () => {
    expectMatches(
      railsCsrfDisabled,
      'skip_before_action :verify_authenticity_token',
      'ruby',
    );
  });

  it('flags protect_from_forgery with: :null_session', () => {
    expectMatches(
      railsCsrfDisabled,
      'protect_from_forgery with: :null_session',
      'ruby',
    );
  });

  it('does not flag protect_from_forgery with: :exception', () => {
    expectNoMatch(
      railsCsrfDisabled,
      'protect_from_forgery with: :exception',
      'ruby',
    );
  });
});

describe('PHP language pack', () => {
  it('flags extract($_GET)', () => {
    expectMatches(phpExtractRequest, '<?php extract($_GET); ?>', 'php');
  });

  it('flags extract($_POST)', () => {
    expectMatches(phpExtractRequest, '<?php extract($_POST); ?>', 'php');
  });

  it('does not flag extract($localArray)', () => {
    expectNoMatch(phpExtractRequest, '<?php extract($config); ?>', 'php');
  });

  it('flags include $page', () => {
    expectMatches(phpDynamicInclude, '<?php include $page; ?>', 'php');
  });

  it('flags require_once($module)', () => {
    expectMatches(phpDynamicInclude, '<?php require_once($module); ?>', 'php');
  });

  it('does not flag include "config.php"', () => {
    expectNoMatch(phpDynamicInclude, '<?php include "config.php"; ?>', 'php');
  });

  it('does not flag include inside a PHP # comment', () => {
    expectNoMatch(phpDynamicInclude, '# include $page;', 'php');
  });

  it('flags unserialize($data)', () => {
    expectMatches(phpUnserialize, '<?php $obj = unserialize($data); ?>', 'php');
  });

  it('does not flag unserialize with allowed_classes => false', () => {
    expectNoMatch(
      phpUnserialize,
      '<?php $obj = unserialize($data, ["allowed_classes" => false]); ?>',
      'php',
    );
  });

  it('flags mysql_query with concatenation', () => {
    expectMatches(
      phpLegacyMysqlConcat,
      '<?php mysql_query("SELECT * FROM users WHERE id = " . $id); ?>',
      'php',
    );
  });

  it('flags mysqli_query with concatenation', () => {
    expectMatches(
      phpLegacyMysqlConcat,
      '<?php mysqli_query($db, "SELECT * FROM t WHERE id = " . $id); ?>',
      'php',
    );
  });
});

describe('VG-INJ-020 prototype-polluting merge', () => {
  const recursiveMerge = [
    'function deepMerge(target, source) {',
    '  for (const key in source) {',
    '    if (typeof source[key] === "object") {',
    '      target[key] = deepMerge(target[key] || {}, source[key]);',
    '    } else {',
    '      target[key] = source[key];',
    '    }',
    '  }',
    '  return target;',
    '}',
  ].join('\n');

  it('flags an unguarded recursive for-in merge', () => {
    expectMatches(prototypePollutingMerge, recursiveMerge, 'javascript', 1);
  });

  it('flags a literal __proto__ write', () => {
    expectMatches(prototypePollutingMerge, 'obj.__proto__.isAdmin = true;', 'javascript', 1);
  });

  it('flags a bracket __proto__ write', () => {
    expectMatches(prototypePollutingMerge, 'target["__proto__"]["polluted"] = value;', 'javascript', 1);
  });

  it('flags a constructor.prototype write', () => {
    expectMatches(prototypePollutingMerge, 'x.constructor.prototype.tainted = 1;', 'javascript', 1);
  });

  it('flags an arrow-function recursive merge', () => {
    const arrow = [
      'const extend = (dst, src) => {',
      '  for (let k in src) {',
      '    if (src[k] && typeof src[k] === "object") dst[k] = extend(dst[k] || {}, src[k]);',
      '    else dst[k] = src[k];',
      '  }',
      '  return dst;',
      '};',
    ].join('\n');
    expectMatches(prototypePollutingMerge, arrow, 'javascript', 1);
  });

  // --- Negatives (Fable's required FP pins) ---
  it('does NOT flag a merge guarded with Object.hasOwn', () => {
    const guarded = [
      'function deepMerge(target, source) {',
      '  for (const key in source) {',
      '    if (!Object.hasOwn(source, key)) continue;',
      '    if (typeof source[key] === "object") target[key] = deepMerge(target[key] || {}, source[key]);',
      '    else target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, guarded, 'javascript');
  });

  it('does NOT flag a merge with an explicit __proto__ key guard', () => {
    const guarded = [
      'function deepMerge(target, source) {',
      '  for (const key in source) {',
      '    if (key === "__proto__" || key === "constructor") continue;',
      '    if (typeof source[key] === "object") target[key] = deepMerge(target[key] || {}, source[key]);',
      '    else target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, guarded, 'javascript');
  });

  it('does NOT flag a merge into an Object.create(null) target', () => {
    const safe = [
      'function deepMerge(source) {',
      '  const target = Object.create(null);',
      '  for (const key in source) {',
      '    target[key] = typeof source[key] === "object" ? deepMerge(source[key]) : source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, safe, 'javascript');
  });

  it('does NOT flag a shallow (non-recursive) for-in copy', () => {
    const shallow = [
      'function assign(target, source) {',
      '  for (const key in source) {',
      '    target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, shallow, 'javascript');
  });

  it('does NOT flag an array index copy loop', () => {
    const arr = [
      'function copy(dst, src) {',
      '  for (let i = 0; i < src.length; i++) {',
      '    dst[i] = copy(dst[i] || [], src[i]);',
      '  }',
      '  return dst;',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, arr, 'javascript');
  });

  it('does NOT flag ordinary prototype-method assignment', () => {
    expectNoMatch(prototypePollutingMerge, 'MyClass.prototype.render = function () { return this.x; };', 'javascript');
  });

  it('does NOT flag a __proto__ comparison or delete', () => {
    expectNoMatch(prototypePollutingMerge, 'if (key === "__proto__") return; delete obj["__proto__"];', 'javascript');
  });

  it('does NOT flag Object.keys iteration (own-keys semantics)', () => {
    const ownKeys = [
      'function deepMerge(target, source) {',
      '  for (const key of Object.keys(source)) {',
      '    target[key] = typeof source[key] === "object" ? deepMerge(target[key] || {}, source[key]) : source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, ownKeys, 'javascript');
  });
});

describe('VG-SMELL-003 long security method', () => {
  function longAuthMethod(): string {
    const lines = ['function authorizeRequest(user, resource, action) {', '  let allowed = false;'];
    for (let i = 0; i < 12; i++) {
      lines.push(`  if (user.role === "role${i}") {`);
      lines.push('    if (resource.owner === user.id) {');
      lines.push('      if (action === "read") {');
      lines.push('        if (user.permission && session.valid) {');
      lines.push('          allowed = true;');
      lines.push('        }');
      lines.push('      }');
      lines.push('    }');
      lines.push('  }');
    }
    lines.push('  return allowed;', '}');
    return lines.join('\n');
  }

  it('flags a long, deeply-nested authorization method as high', () => {
    const m = longSecurityMethod.match(ctx(longAuthMethod(), 'javascript'));
    expect(m.length).toBe(1);
    expect(m[0]?.severity).toBe('high');
  });

  it('flags a long security method in python', () => {
    const lines = ['def validate_token(user, token):', '    ok = False'];
    for (let i = 0; i < 18; i++) {
      lines.push(`    if token.kind == "k${i}":`);
      lines.push('        if user.session:');
      lines.push('            if token.valid:');
      lines.push('                if user.permission:');
      lines.push('                    ok = True');
    }
    lines.push('    return ok');
    const m = longSecurityMethod.match(ctx(lines.join('\n'), 'python'));
    expect(m.length).toBe(1);
    expect(m[0]?.severity).toBe('high');
  });

  it('does NOT flag a short auth method', () => {
    const short = [
      'function login(user, password) {',
      '  if (!user) return false;',
      '  const ok = verify(user.hash, password);',
      '  if (!ok) return false;',
      '  return issueToken(user);',
      '}',
    ].join('\n');
    expectNoMatch(longSecurityMethod, short, 'javascript');
  });

  it('does NOT flag a flat switch dispatcher (many branches, shallow nesting)', () => {
    const lines = ['function handleAuthEvent(evt) {', '  switch (evt.type) {'];
    for (let i = 0; i < 30; i++) lines.push(`    case "e${i}": return validate(evt);`);
    lines.push('    default: return null;', '  }', '}');
    expectNoMatch(longSecurityMethod, lines.join('\n'), 'javascript');
  });

  it('does NOT flag a long method with NO security keyword', () => {
    const lines = ['function computeReport(rows) {', '  let total = 0;'];
    for (let i = 0; i < 12; i++) {
      lines.push(`  if (rows[${i}]) {`);
      lines.push('    if (rows[i].active) {');
      lines.push('      if (rows[i].value > 0) {');
      lines.push('        if (rows[i].tax) {');
      lines.push('          total += rows[i].value;');
      lines.push('        }');
      lines.push('      }');
      lines.push('    }');
      lines.push('  }');
    }
    lines.push('  return total;', '}');
    expectNoMatch(longSecurityMethod, lines.join('\n'), 'javascript');
  });

  it('does NOT double-report a qualifying method containing an inner helper', () => {
    const lines = ['function authorizeRequest(user) {', '  let allowed = false;'];
    lines.push('  function innerCheck(u) { return u && u.role; }');
    for (let i = 0; i < 12; i++) {
      lines.push(`  if (user.role === "role${i}") {`);
      lines.push('    if (user.owner) {');
      lines.push('      if (user.session) {');
      lines.push('        if (user.permission) {');
      lines.push('          allowed = innerCheck(user);');
      lines.push('        }');
      lines.push('      }');
      lines.push('    }');
      lines.push('  }');
    }
    lines.push('  return allowed;', '}');
    const m = longSecurityMethod.match(ctx(lines.join('\n'), 'javascript'));
    expect(m.length).toBe(1);
  });
});

describe('VG-SMELL-012 primitive role check', () => {
  const threeSites = [
    'function canDelete(user) {',
    '  if (user.role === "admin") return true;',
    '  if (req.user.role == "owner") return true;',
    '  if (currentUser.userType === "manager") return true;',
    '  return false;',
    '}',
  ].join('\n');

  it('flags three or more hardcoded role comparisons', () => {
    const m = primitiveRoleCheck.match(ctx(threeSites, 'javascript'));
    expect(m.length).toBe(3);
  });

  it('escalates an admin/root literal to high', () => {
    const m = primitiveRoleCheck.match(ctx(threeSites, 'javascript'));
    const adminSite = m.find((x) => x.variables?.lit?.toLowerCase() === 'admin');
    expect(adminSite?.severity).toBe('high');
    const ownerSite = m.find((x) => x.variables?.lit?.toLowerCase() === 'owner');
    expect(ownerSite?.severity).toBeUndefined();
  });

  it('flags a Yoda-style comparison', () => {
    const yoda = [
      'if ("admin" === user.role) grant();',
      'if ("root" == account.role) grant();',
      'if ("editor" === member.permission) grant();',
    ].join('\n');
    expect(primitiveRoleCheck.match(ctx(yoda, 'javascript')).length).toBe(3);
  });

  it('flags python role comparisons', () => {
    const py = [
      'if user.role == "admin":',
      '    allow()',
      'if account.role == "owner":',
      '    allow()',
      'if member.permission == "editor":',
      '    allow()',
    ].join('\n');
    expect(primitiveRoleCheck.match(ctx(py, 'python')).length).toBe(3);
  });

  // --- Negatives ---
  it('does NOT flag when fewer than three sites', () => {
    const two = [
      'if (user.role === "admin") return true;',
      'if (user.role === "owner") return true;',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, two, 'javascript');
  });

  it('does NOT flag when an enum/constant layer is present', () => {
    const enumed = [
      'const Roles = Object.freeze({ ADMIN: "admin", OWNER: "owner", USER: "user" });',
      'if (user.role === "admin") return true;',
      'if (req.user.role == "owner") return true;',
      'if (currentUser.role === "user") return true;',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, enumed, 'javascript');
  });

  it('does NOT flag OAuth scope comparisons', () => {
    const scopes = [
      'if (token.scope === "user") return true;',
      'if (grant.scope == "read") return true;',
      'if (auth.scope === "write") return true;',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, scopes, 'javascript');
  });

  it('does NOT flag test assertions', () => {
    const asserts = [
      'expect(user.role).toBe("admin");',
      'assert user.role == "owner"',
      'it("role is admin", () => { expect(u.role === "admin").toBe(true); });',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, asserts, 'javascript');
  });

  it('does NOT flag comparisons against a constant (no string literal)', () => {
    const consts = [
      'if (user.role === Role.ADMIN) return true;',
      'if (req.user.role === Role.OWNER) return true;',
      'if (currentUser.role === Role.MANAGER) return true;',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, consts, 'javascript');
  });
});

describe('VG-SMELL-004 security swiss army knife', () => {
  function ctxF(content: string, filePath: string, language = 'javascript'): RuleContext {
    return { content, lines: content.split('\n'), language, filePath };
  }

  const swiss = [
    'class SecurityUtils {',
    '  static hashPassword(p) { return bcrypt.hash(p); }',
    '  static generateJwt(u) { return jwt.sign(u); }',
    '  static sanitizeHtml(s) { return escape(s); }',
    '  static validateEmail(e) { return /x/.test(e); }',
    '  static encryptFile(f) { return cipher(f); }',
    '  static checkAdminRole(u) { return u.role; }',
    '  static parseCsv(t) { return t.split(","); }',
    '  static calculateTax(a) { return a * 0.1; }',
    '}',
  ].join('\n');

  it('flags a SecurityUtils grab-bag mixing crypto/auth/parsing/business as high', () => {
    const m = securitySwissArmyKnife.match(ctxF(swiss, 'src/SecurityUtils.js'));
    expect(m.length).toBe(1);
    expect(m[0]?.severity).toBe('high');
    expect(m[0]?.startLine).toBe(1);
  });

  it('flags via the filename gate even without a matching class name', () => {
    const fns = [
      'export function hashPassword(p) { return bcrypt.hash(p); }',
      'export function loginUser(u) { return session.start(u); }',
      'export function sanitizeInput(s) { return escape(s); }',
      'export function parseCsvFile(t) { return t.split(","); }',
      'export function calculateInvoiceTotal(a) { return a; }',
    ].join('\n');
    const m = securitySwissArmyKnife.match(ctxF(fns, 'src/utils.js'));
    expect(m.length).toBe(1);
  });

  // --- Negatives ---
  it('does NOT flag a cohesive single-domain crypto util', () => {
    const cohesive = [
      'class CryptoUtils {',
      '  static hash(x) { return sha256(x); }',
      '  static encrypt(x) { return cipher(x); }',
      '  static decrypt(x) { return decipher(x); }',
      '  static hmac(x) { return mac(x); }',
      '  static sign(x) { return signer(x); }',
      '}',
    ].join('\n');
    expect(securitySwissArmyKnife.match(ctxF(cohesive, 'src/crypto-utils.js'))).toEqual([]);
  });

  it('does NOT flag a test-helper file even if it is a grab-bag', () => {
    expect(securitySwissArmyKnife.match(ctxF(swiss, 'src/utils.test.js'))).toEqual([]);
  });

  it('does NOT flag a barrel/re-export file with no function bodies', () => {
    const barrel = [
      'export { hashPassword } from "./crypto";',
      'export { login } from "./auth";',
      'export { parseCsv } from "./parse";',
    ].join('\n');
    expect(securitySwissArmyKnife.match(ctxF(barrel, 'src/utils/index.js'))).toEqual([]);
  });

  it('does NOT flag a non-utility file name with no utility class', () => {
    expect(securitySwissArmyKnife.match(ctxF(swiss.replace('SecurityUtils', 'AccountController'), 'src/account.js'))).toEqual([]);
  });
});

describe('VG-AISC-001 hallucinated dependency', () => {
  it('flags an edit-distance-1 npm typo (expresss)', () => {
    const m = hallucinatedDependency.match(ctx("const e = require('expresss');", 'javascript'));
    expect(m.length).toBe(1);
    expect(m[0]?.variables?.didYouMean).toBe('express');
  });

  it('flags an adjacent transposition (lodahs -> lodash)', () => {
    const m = hallucinatedDependency.match(ctx("import _ from 'lodahs';", 'javascript'));
    expect(m.length).toBe(1);
    expect(m[0]?.variables?.didYouMean).toBe('lodash');
  });

  it('flags an edit-distance-1 PyPI typo (reqeusts -> requests)', () => {
    const m = hallucinatedDependency.match(ctx('import reqeusts', 'python'));
    expect(m.length).toBe(1);
    expect(m[0]?.variables?.didYouMean).toBe('requests');
  });

  it('flags a curated hallucinated name with high confidence', () => {
    const m = hallucinatedDependency.match(ctx("require('huggingface-cli');", 'javascript'));
    expect(m.length).toBe(1);
    expect(m[0]?.confidence).toBe('high');
  });

  // --- Negatives (the precision contract) ---
  it('does NOT flag a popular package', () => {
    expectNoMatch(hallucinatedDependency, "import express from 'express';", 'javascript');
  });

  it('does NOT flag a subpath of a popular package', () => {
    expectNoMatch(hallucinatedDependency, "import merge from 'lodash/merge';", 'javascript');
  });

  it('does NOT flag a relative import', () => {
    expectNoMatch(hallucinatedDependency, "import x from './utils';", 'javascript');
  });

  it('does NOT flag a scoped package', () => {
    expectNoMatch(hallucinatedDependency, "import core from '@babel/core';", 'javascript');
  });

  it('does NOT flag a node builtin', () => {
    expectNoMatch(hallucinatedDependency, "const fs = require('fs');", 'javascript');
  });

  it('does NOT flag an UNKNOWN but not-near-miss package (the contract)', () => {
    expectNoMatch(hallucinatedDependency, "const w = require('my-internal-corp-widget');", 'javascript');
  });

  it('does NOT flag a python stdlib import', () => {
    expectNoMatch(hallucinatedDependency, 'import os\nfrom pathlib import Path', 'python');
  });

  it('does NOT flag a popular python package', () => {
    expectNoMatch(hallucinatedDependency, 'import numpy as np\nimport requests', 'python');
  });

  it('does NOT flag an unknown-not-near-miss python module', () => {
    expectNoMatch(hallucinatedDependency, 'import mycompanyinternallib', 'python');
  });
});

describe('0.2.x adversarial-review regressions (verified false positives)', () => {
  function ctxF(content: string, filePath: string, language = 'javascript'): RuleContext {
    return { content, lines: content.split('\n'), language, filePath };
  }

  // VG-SMELL-004: 'hash' in a hashmap-key helper must not read as a crypto domain.
  it('SMELL-004 does NOT flag a CacheUtils whose only "security" signal is hashKey', () => {
    const cache = [
      'class CacheUtils {',
      '  static hashKey(k) { return fnv1a(k) >>> 0; }',
      '  static serializeEntry(e) { return JSON.stringify(e); }',
      '  static computeSize(e) { return Buffer.byteLength(e); }',
      '  static parseKey(raw) { return raw.split(":"); }',
      '  static formatKey(ns, k) { return ns + ":" + k; }',
      '}',
    ].join('\n');
    expect(securitySwissArmyKnife.match(ctxF(cache, 'src/CacheUtils.js'))).toEqual([]);
  });

  // VG-SMELL-004: a parser that handles auth-shaped strings is parsing, not auth.
  it('SMELL-004 does NOT flag a decoder that only parses auth-shaped strings', () => {
    const dec = [
      'class DecoderUtils {',
      '  static parseToken(raw) { return raw.split("."); }',
      '  static parseSession(raw) { return JSON.parse(raw); }',
      '  static parseAuthHeader(h) { return h.replace("Bearer ", ""); }',
      '  static parseCsv(t) { return t.split(","); }',
      '  static renderReport(rows) { return rows.join("\n"); }',
      '}',
    ].join('\n');
    expect(securitySwissArmyKnife.match(ctxF(dec, 'src/DecoderUtils.js'))).toEqual([]);
  });

  // VG-AISC-001: a method literally named `import`/`require` is a call, not a load.
  it('AISC-001 does NOT flag a member-access .import()/.require() call', () => {
    const code = "const r = makeRegistry();\nr.import('expresss', { lazy: true });\nr.require('winstonn');";
    expect(hallucinatedDependency.match(ctx(code, 'javascript'))).toEqual([]);
  });

  // VG-INJ-020: a proto sink printed inside a diagnostic string is not a write.
  it('INJ-020 does NOT flag a proto sink that only appears inside a string literal', () => {
    const guard = [
      'const FORBIDDEN = ["__proto__", "constructor", "prototype"];',
      'function assertSafeKey(key) {',
      '  if (FORBIDDEN.includes(key)) {',
      '    throw new Error(`Refusing to set .__proto__ = on the target for ${key}`);',
      '  }',
      '  return key;',
      '}',
    ].join('\n');
    expect(prototypePollutingMerge.match(ctx(guard, 'javascript'))).toEqual([]);
  });

  // VG-INJ-020: a module-scope denylist consulted via Set.has(key) is a guard.
  it('INJ-020 does NOT flag a merge guarded by a hoisted Set.has denylist', () => {
    const hoisted = [
      'const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);',
      'function deepMerge(target, source) {',
      '  for (const key in source) {',
      '    if (BLOCKED.has(key)) continue;',
      '    if (source[key] && typeof source[key] === "object") {',
      '      target[key] = deepMerge(target[key] ?? {}, source[key]);',
      '    } else {',
      '      target[key] = source[key];',
      '    }',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expect(prototypePollutingMerge.match(ctx(hoisted, 'javascript'))).toEqual([]);
  });

  // VG-SMELL-012 extra adversarial negatives (its workflow generator errored).
  it('SMELL-012 does NOT flag a switch on a role (no comparison operator)', () => {
    const sw = [
      'switch (user.role) {',
      '  case "admin": return grantAll();',
      '  case "owner": return grantOwner();',
      '  case "member": return grantMember();',
      '}',
    ].join('\n');
    expect(primitiveRoleCheck.match(ctx(sw, 'javascript'))).toEqual([]);
  });

  it('SMELL-012 does NOT flag role comparisons against variables (no string literal)', () => {
    const vars = [
      'if (user.role === adminRole) return true;',
      'if (user.role === ownerRole) return true;',
      'if (user.role === managerRole) return true;',
    ].join('\n');
    expect(primitiveRoleCheck.match(ctx(vars, 'javascript'))).toEqual([]);
  });
});

describe('0.2.x completeness-review regressions (Fable-found, scanner-verified)', () => {
  // BLOCKER: from X import Y turned the imported SYMBOL into a package candidate.
  it('AISC-001 does NOT flag the imported symbol of a from-import (from flask import request)', () => {
    expectNoMatch(hallucinatedDependency, 'from flask import request', 'python');
    expectNoMatch(hallucinatedDependency, 'from fastapi import Request, Response', 'python');
  });

  it('AISC-001 still flags a hallucinated MODULE in a from-import', () => {
    expectMatches(hallucinatedDependency, 'from reqeusts import get', 'python', 1);
  });

  // MAJOR: real popular packages that are edit-distance-1 of a listed name.
  it('AISC-001 does NOT flag real packages that are DL-1 of a listed one (preact, enquirer)', () => {
    expectNoMatch(hallucinatedDependency, "import { h } from 'preact';", 'javascript');
    expectNoMatch(hallucinatedDependency, "const e = require('enquirer');", 'javascript');
  });

  // MAJOR: python # comments must not inflate SMELL-003 branch/nesting metrics.
  it('SMELL-003 does NOT fire from keywords inside python # comments', () => {
    const lines = ['def summarize(user, resource):', '    total = 0'];
    for (let i = 0; i < 90; i++) lines.push('    # if the role or the token and the session and auth or login');
    lines.push('    if resource:', '        total += 1', '    return total');
    expectNoMatch(longSecurityMethod, lines.join('\n'), 'python');
  });

  // MAJOR: an apostrophe in a python # comment must not blank real code (FN).
  it('SMELL-003 STILL fires on a genuine long method containing a # don\'t comment', () => {
    const lines = ['def authorize(user, resource, action):', "    # don't skip this", '    allowed = False'];
    for (let i = 0; i < 18; i++) {
      lines.push(`    if user.role == "r${i}":`);
      lines.push('        if resource.owner:');
      lines.push('            if user.session:');
      lines.push('                if user.permission:');
      lines.push('                    allowed = True');
    }
    lines.push('    return allowed');
    const m = longSecurityMethod.match(ctx(lines.join('\n'), 'python'));
    expect(m.length).toBe(1);
  });

  // MAJOR: a template literal containing an apostrophe must not desync blankJs (FN).
  it('INJ-020 STILL fires on a real proto write after a template literal with an apostrophe', () => {
    const code = "const msg = `can't merge these`;\nobj.__proto__.polluted = { admin: true };";
    const m = prototypePollutingMerge.match(ctx(code, 'javascript'));
    expect(m.length).toBeGreaterThanOrEqual(1);
  });
});

describe('0.2.x final-review regressions (Fable round 2, scanner-verified)', () => {
  // A1: real packages that are DL-1 of a listed name.
  it('AISC-001 does NOT flag psycopg (real, DL-1 of psycopg2) or merge2 (DL-1 of merge)', () => {
    expectNoMatch(hallucinatedDependency, 'import psycopg', 'python');
    expectNoMatch(hallucinatedDependency, "const m = require('merge2');", 'javascript');
  });

  // A2: role comparisons inside string literals (doc/example/i18n strings).
  it('SMELL-012 does NOT flag role comparisons written inside string literals', () => {
    const docs = [
      "const ex1 = 'if (user.role === \"admin\") grant();';",
      "const ex2 = 'if (user.role === \"owner\") grant();';",
      "const ex3 = 'if (user.role === \"editor\") grant();';",
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, docs, 'javascript');
  });

  // A3: a regex literal containing a quote must not desync the JS blanker.
  it('INJ-020 does NOT fire from a proto sink in a string after a quote-class regex literal', () => {
    const code = [
      "const QUOTE = /[\"']/;",
      'function validate(k) {',
      '  throw new Error("cannot set x.__proto__ = payload for " + k);',
      '}',
    ].join('\n');
    expectNoMatch(prototypePollutingMerge, code, 'javascript');
  });

  // A5: a $-prefixed loop var must not break the dynamic recursion regex.
  it('INJ-020 STILL fires on a recursive merge using a $-prefixed loop variable', () => {
    const code = [
      'function deepMerge(target, source) {',
      '  for (const $k in source) {',
      '    if (typeof source[$k] === "object") target[$k] = deepMerge(target[$k] || {}, source[$k]);',
      '    else target[$k] = source[$k];',
      '  }',
      '  return target;',
      '}',
    ].join('\n');
    expect(prototypePollutingMerge.match(ctx(code, 'javascript')).length).toBeGreaterThanOrEqual(1);
  });

  // AUTHZ escalation is case-insensitive on the word tokens (checkUserPermissions).
  it('SMELL-003 escalates a long method with checkUserPermissions (capital P) to high', () => {
    const lines = ['function checkUserPermissions(user, resource) {', '  let ok = false;'];
    for (let i = 0; i < 12; i++) {
      lines.push(`  if (user.tier === ${i}) {`);
      lines.push('    if (resource.ownerId === user.id) {');
      lines.push('      if (user.session && user.session.valid) {');
      lines.push('        if (user.active) {');
      lines.push('          ok = true;');
      lines.push('        }');
      lines.push('      }');
      lines.push('    }');
      lines.push('  }');
    }
    lines.push('  return ok;', '}');
    const m = longSecurityMethod.match(ctx(lines.join('\n'), 'javascript'));
    expect(m.length).toBe(1);
    expect(m[0]?.severity).toBe('high');
  });
});
