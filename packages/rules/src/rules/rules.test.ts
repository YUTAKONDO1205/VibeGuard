// vibeguard:disable-file
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { describe, expect, it } from 'vitest';
import type { RuleContext, RuleDefinition } from '../rule-types.js';
import { evalUsage, sqlStringConcat, innerHtmlAssignment, dangerousDeserialization } from './injection.js';
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
