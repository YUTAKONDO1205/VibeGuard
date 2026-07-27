// vibeguard:disable-file VG-SMELL-012 VG-SMELL-003 VG-QUAL-002
// Test fixtures below contain intentional primitive role checks and long
// security methods to exercise the rules they are testing.
//
// 17z-e / 17z-f-lite — the LANGUAGE-COVERAGE half of the single-file design
// smells. Kept out of rules.test.ts on purpose: that file is the shape/behaviour
// suite for every rule, this one answers a narrower question — "does VG-SMELL-012
// hold up in java/go/kotlin, and does VG-SMELL-003 see the TypeScript heads it
// used to miss" — and each half owns the negative and timing evidence for its own
// claim.
import { describe, expect, it } from 'vitest';
import type { RuleContext, RuleDefinition } from '../rule-types.js';
import { longSecurityMethod, primitiveRoleCheck } from './design-smells-single.js';
import { REGEX_INPUT_CAP } from '../matcher-utils.js';

function ctx(content: string, language?: string): RuleContext {
  return { content, lines: content.split('\n'), language };
}

function expectNoMatch(rule: RuleDefinition, content: string, language?: string) {
  expect(rule.match(ctx(content, language))).toEqual([]);
}

// --- 17z-e: VG-SMELL-012 in java / go / kotlin --------------------------------

describe('VG-SMELL-012 — java', () => {
  const javaEquals = [
    'public class AccessService {',
    '  public boolean canAccess(User user, Account account) {',
    '    if (user.getRole().equals("admin")) return true;',
    '    if ("owner".equals(account.getRole())) return true;',
    '    if (account.getPermission().equalsIgnoreCase("editor")) return true;',
    '    return false;',
    '  }',
    '}',
  ].join('\n');

  it('flags three .equals role comparisons', () => {
    const m = primitiveRoleCheck.match(ctx(javaEquals, 'java'));
    expect(m.length).toBe(3);
  });

  it('escalates the admin literal to high', () => {
    const m = primitiveRoleCheck.match(ctx(javaEquals, 'java'));
    expect(m.find((x) => x.variables?.lit?.toLowerCase() === 'admin')?.severity).toBe('high');
    expect(m.find((x) => x.variables?.lit?.toLowerCase() === 'owner')?.severity).toBeUndefined();
  });

  it('flags the (buggy but common) == form too', () => {
    const eq = [
      'class A {',
      '  boolean f(User u, Account a, Member m) {',
      '    if (u.role == "admin") return true;',
      '    if (a.userType == "manager") return true;',
      '    if (m.permission == "editor") return true;',
      '    return false;',
      '  }',
      '}',
    ].join('\n');
    expect(primitiveRoleCheck.match(ctx(eq, 'java')).length).toBe(3);
  });

  // --- Negatives ---
  it('does NOT flag when an enum aggregates the roles', () => {
    const enumed = [
      'public enum Role { ADMIN, OWNER, EDITOR }',
      'class A {',
      '  boolean f(User u, Account a, Member m) {',
      '    if (u.getRole().equals("admin")) return true;',
      '    if (a.getRole().equals("owner")) return true;',
      '    if (m.getPermission().equals("editor")) return true;',
      '    return false;',
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, enumed, 'java');
  });

  it('does NOT flag when a String constant table aggregates the roles', () => {
    const consts = [
      'class Roles {',
      '  static final String ROLE_ADMIN = "admin";',
      '  static final String ROLE_OWNER = "owner";',
      '}',
      'class A {',
      '  boolean f(User u, Account a, Member m) {',
      '    if (u.getRole().equals("admin")) return true;',
      '    if (a.getRole().equals("owner")) return true;',
      '    if (m.getPermission().equals("editor")) return true;',
      '    return false;',
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, consts, 'java');
  });

  it('does NOT flag when a declarative policy annotation is present', () => {
    const spring = [
      'class A {',
      '  @PreAuthorize("hasRole(\'ADMIN\')")',
      '  boolean f(User u, Account a, Member m) {',
      '    if (u.getRole().equals("admin")) return true;',
      '    if (a.getRole().equals("owner")) return true;',
      '    if (m.getPermission().equals("editor")) return true;',
      '    return false;',
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, spring, 'java');
  });

  it('stays silent on a file containing a text block (raw string not modelled)', () => {
    // Three genuine comparisons, but the file also holds a `"""` text block, whose
    // interior neither blanker can classify. The arm must skip the WHOLE file
    // rather than risk counting a comparison that only exists inside prose.
    const withTextBlock = [
      'class A {',
      '  String doc = """',
      '    role == "admin" is how the old code did it',
      '    """;',
      '  boolean f(User u, Account a, Member m) {',
      '    if (u.role == "admin") return true;',
      '    if (a.userType == "manager") return true;',
      '    if (m.permission == "editor") return true;',
      '    return false;',
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, withTextBlock, 'java');
  });

  it('does NOT flag comparisons that only appear inside string literals', () => {
    const inStrings = [
      'class A {',
      '  String a = "if (u.role == \\"admin\\") deny();";',
      '  String b = "if (u.role == \\"owner\\") deny();";',
      '  String c = "if (u.role == \\"editor\\") deny();";',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, inStrings, 'java');
  });

  it('does NOT flag two sites (below the three-site threshold)', () => {
    const two = [
      'class A {',
      '  boolean f(User u, Account a) {',
      '    if (u.getRole().equals("admin")) return true;',
      '    if (a.getRole().equals("owner")) return true;',
      '    return false;',
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, two, 'java');
  });
});

describe('VG-SMELL-012 — go', () => {
  const goSites = [
    'package auth',
    '',
    'func canAccess(u User, a Account, m Member) bool {',
    '\tif u.Role == "admin" {',
    '\t\treturn true',
    '\t}',
    '\tif a.UserType == "manager" {',
    '\t\treturn true',
    '\t}',
    '\tif m.Permission == "editor" {',
    '\t\treturn true',
    '\t}',
    '\treturn false',
    '}',
  ].join('\n');

  it('flags three hardcoded role comparisons', () => {
    expect(primitiveRoleCheck.match(ctx(goSites, 'go')).length).toBe(3);
  });

  it('does NOT flag when a named role type aggregates them', () => {
    const typed = `type Role string\n${goSites}`;
    expectNoMatch(primitiveRoleCheck, typed, 'go');
  });

  it('does NOT flag when a const/iota enumeration is present', () => {
    const iota = ['const (', '\tRoleAdmin = iota', '\tRoleOwner', ')', goSites].join('\n');
    expectNoMatch(primitiveRoleCheck, iota, 'go');
  });

  it('does NOT count comparisons inside a backtick raw string', () => {
    // The backtick raw string IS modelled (blankJsLiterals treats it as a template
    // literal), so these three comparisons are recognised as text, not code, and
    // the file drops below the three-site threshold.
    const rawOnly = [
      'package tpl',
      '',
      'const doc = `',
      '  if u.Role == "admin" { }',
      '  if a.UserType == "manager" { }',
      '  if m.Permission == "editor" { }',
      '`',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, rawOnly, 'go');
  });

  it('still flags real comparisons in a file that also has struct tags', () => {
    // The regression the "skip any file containing a backtick" design would have
    // caused: struct tags put a backtick in nearly every real Go file.
    const withTags = [
      'package auth',
      '',
      'type User struct {',
      '\tName string `json:"name"`',
      '}',
      goSites,
    ].join('\n');
    expect(primitiveRoleCheck.match(ctx(withTags, 'go')).length).toBe(3);
  });
});

describe('VG-SMELL-012 — kotlin', () => {
  const kotlinSites = [
    'class AccessService {',
    '    fun canAccess(u: User, a: Account, m: Member): Boolean {',
    '        if (u.role == "admin") return true',
    '        if (a.userType == "manager") return true',
    '        if (m.permission == "editor") return true',
    '        return false',
    '    }',
    '}',
  ].join('\n');

  it('flags three hardcoded role comparisons', () => {
    expect(primitiveRoleCheck.match(ctx(kotlinSites, 'kotlin')).length).toBe(3);
  });

  it('does NOT flag when an enum class aggregates the roles', () => {
    expectNoMatch(primitiveRoleCheck, `enum class Role { ADMIN, OWNER }\n${kotlinSites}`, 'kotlin');
  });

  it('does NOT flag when a sealed class aggregates the roles', () => {
    expectNoMatch(primitiveRoleCheck, `sealed class Role\n${kotlinSites}`, 'kotlin');
  });

  it('does NOT flag when const vals aggregate the roles', () => {
    expectNoMatch(
      primitiveRoleCheck,
      `object Perms {\n    const val ROLE_ADMIN = "admin"\n}\n${kotlinSites}`,
      'kotlin',
    );
  });

  it('stays silent on a file containing a raw string', () => {
    const raw = ['val doc = """', '  role == "admin"', '"""', kotlinSites].join('\n');
    expectNoMatch(primitiveRoleCheck, raw, 'kotlin');
  });
});

describe('VG-SMELL-012 — the js/ts/python arm is unchanged by 17z-e', () => {
  // The per-language veto and the raw-string skip are keyed by language, so the
  // three shipped languages must take exactly the path they took before. A
  // triple-quoted python docstring in particular must NOT be read as a Java text
  // block and silence the file.
  const py = [
    'def can_access(user, req, member):',
    '    """Docstring mentioning role == "admin" in prose."""',
    '    if user.role == "admin":',
    '        return True',
    '    if req.user.role == "owner":',
    '        return True',
    '    if member.permission == "editor":',
    '        return True',
    '    return False',
  ].join('\n');

  it('still flags python role comparisons despite the triple-quoted docstring', () => {
    expect(primitiveRoleCheck.match(ctx(py, 'python')).length).toBe(3);
  });

  it('survives a prototype-chain language name', () => {
    // `scan({ …, language })` takes whatever the caller passes. A bare index into
    // the language-keyed veto maps would resolve `'constructor'` to an inherited
    // function and throw inside match(), which the analyzer's per-rule try/catch
    // would turn into "this rule produced nothing" — a silent suppression channel.
    const src = [
      'if (user.role === "admin") return true;',
      'if (account.userType === "manager") return true;',
      'if (member.permission === "editor") return true;',
    ].join('\n');
    for (const language of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      expect(() => primitiveRoleCheck.match(ctx(src, language))).not.toThrow();
      expect(primitiveRoleCheck.match(ctx(src, language)).length).toBe(3);
    }
  });

  it('does not accept .equals() in javascript', () => {
    const js = [
      'function canAccess(user, account, member) {',
      '  if (user.role.equals("admin")) return true;',
      '  if (account.userType.equals("manager")) return true;',
      '  if (member.permission.equals("editor")) return true;',
      '  return false;',
      '}',
    ].join('\n');
    expectNoMatch(primitiveRoleCheck, js, 'javascript');
  });
});

// --- 17z-f-lite: VG-SMELL-003 TypeScript heads --------------------------------

/** A body that clears MIN_LINES(80) / MIN_NESTING(4) / MIN_BRANCHES(10). */
function qualifyingBody(): string[] {
  const out: string[] = ['  let allowed = false;'];
  for (let i = 0; i < 12; i += 1) {
    out.push(`  if (user.permissions[${i}]) {`);
    out.push('    for (const p of user.permissions) {');
    out.push('      while (p.pending) {');
    out.push('        if (p.role === scope || p.token) {');
    out.push('          allowed = true;');
    out.push('        }');
    out.push('      }');
    out.push('    }');
    out.push('  }');
  }
  out.push('  return allowed;');
  return out;
}

describe('VG-SMELL-003 — TypeScript heads (17z-f-lite)', () => {
  it('flags a method with a return-type annotation', () => {
    const src = [
      'class Guard {',
      '  async authorizeRequest(user: User, resource: string): Promise<boolean> {',
      ...qualifyingBody(),
      '  }',
      '}',
    ].join('\n');
    const m = longSecurityMethod.match(ctx(src, 'typescript'));
    expect(m.length).toBe(1);
    expect(m[0]?.severity).toBe('high');
  });

  it('flags a method with generics directly after the name', () => {
    const src = [
      'class Guard {',
      '  checkPermissions<T extends Resource>(user: User, r: T) {',
      ...qualifyingBody(),
      '  }',
      '}',
    ].join('\n');
    expect(longSecurityMethod.match(ctx(src, 'typescript')).length).toBe(1);
  });

  it('flags a method with generics AND a return-type annotation', () => {
    const src = [
      'class Guard {',
      '  private async authorize<T>(user: User, r: T): Promise<Result<T, Error>> {',
      ...qualifyingBody(),
      '  }',
      '}',
    ].join('\n');
    expect(longSecurityMethod.match(ctx(src, 'typescript')).length).toBe(1);
  });

  it('flags a generic function declaration', () => {
    const src = ['function validateSession<T>(session: T) {', ...qualifyingBody(), '}'].join('\n');
    expect(longSecurityMethod.match(ctx(src, 'typescript')).length).toBe(1);
  });

  it('does not double-report a return-type method that already matched', () => {
    // The outermost-wins guard has to survive the new alternatives: the inner
    // helper's own annotated head sits inside the flagged block.
    const src = [
      'class Guard {',
      '  async authorizeRequest(user: User): Promise<boolean> {',
      ...qualifyingBody().slice(0, -1),
      '    const check = (p: Perm): boolean => p.role === "x";',
      '    return check(user.permissions[0]);',
      '  }',
      '}',
    ].join('\n');
    expect(longSecurityMethod.match(ctx(src, 'typescript')).length).toBe(1);
  });

  // --- Negatives: shapes the new alternatives must NOT turn into heads ---
  it('does NOT treat a switch case label as a function head', () => {
    const src = [
      'function dispatch(evt) {',
      '  switch (evt.type) {',
      '    case resolve(evt): {',
      ...qualifyingBody(),
      '    }',
      '  }',
      '}',
    ].join('\n');
    // The only qualifying head is `dispatch` itself, never `resolve`.
    const m = longSecurityMethod.match(ctx(src, 'typescript'));
    expect(m.every((x) => !x.evidence.startsWith('resolve'))).toBe(true);
  });

  it('does NOT flag a short annotated method', () => {
    const src = [
      'class Guard {',
      '  authorize(user: User): boolean {',
      '    return user.role === "admin";',
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(longSecurityMethod, src, 'typescript');
  });

  it('does NOT flag a long annotated method with no security keyword', () => {
    const src = [
      'class Report {',
      '  buildTotals(rows: Row[]): number {',
      ...qualifyingBody()
        .join('\n')
        .replace(/user\.permissions/g, 'rows.cells')
        .replace(/p\.role === scope \|\| p\.token/g, 'p.qty > 0')
        .replace(/for \(const p of rows\.cells\)/g, 'for (const p of rows.cells)')
        .split('\n'),
      '  }',
      '}',
    ].join('\n');
    expectNoMatch(longSecurityMethod, src, 'typescript');
  });
});

// --- D3: the 3-second contract, for the shapes this change added --------------

describe('17z-e / 17z-f-lite regex shapes stay linear (D3)', () => {
  // Mirrors redos-invariant.test.ts: adversarial inputs just under the input cap
  // so the cap does not mask a slow pattern. Those live in analyzer-core and run
  // the FULL rule set over python/javascript/ruby/go/php/java/c/cpp — kotlin is
  // not in that list, and neither is the annotated-head shape, so the inputs this
  // change made reachable are covered HERE.
  const N = REGEX_INPUT_CAP - 100;
  // A single rule over ~50 KB is tens of milliseconds when linear and seconds when
  // it backtracks; 1500 ms sits an order of magnitude from both and inside DESIGN
  // §11.1's 3 s single-file budget. If this flakes, the pattern got slow — fix the
  // pattern, do not raise the budget.
  const BUDGET_MS = 1_500;

  const ADVERSARIAL: Array<{ name: string; content: string; languages: string[] }> = [
    // The .equals shapes: a near-miss that enters the identifier run and fails at
    // the literal, repeated to the cap.
    {
      name: 'equals-near-miss',
      content: 'u.getRole().equals("admi\n'.repeat(N / 25),
      languages: ['java', 'kotlin'],
    },
    // Yoda-equals near-miss.
    {
      name: 'equals-yoda-near-miss',
      content: '"admin".equals(u.getRol\n'.repeat(N / 24),
      languages: ['java', 'kotlin'],
    },
    // One enormous line: the shape that breaks any pattern whose whitespace runs
    // are not horizontal-only or not bounded.
    {
      name: 'single-long-line',
      content: `if (u.role${' '.repeat(N / 2)}== "admin")${' '.repeat(N / 2)}{`,
      languages: ['java', 'kotlin', 'go', 'typescript'],
    },
    // The per-language veto patterns' own near-misses.
    { name: 'go-type-near-miss', content: 'type UserRol strin\n'.repeat(N / 19), languages: ['go'] },
    {
      name: 'kotlin-enum-near-miss',
      content: 'enum class Rol {\n'.repeat(N / 17),
      languages: ['kotlin'],
    },
    { name: 'java-final-near-miss', content: 'final String ROL = 1;\n'.repeat(N / 22), languages: ['java'] },
    // Backtick soup: the Go arm runs blankJsLiterals over the whole file.
    { name: 'go-backtick-soup', content: '`json:"role"`\n'.repeat(N / 14), languages: ['go'] },
    // 17z-f-lite: the annotated-head and generics alternatives, entered then failed.
    {
      name: 'annotated-head-near-miss',
      content: 'authorize(a: string): Promise<voi\n'.repeat(N / 34),
      languages: ['typescript'],
    },
    {
      name: 'generics-head-near-miss',
      content: 'fetchAll<T extends Resource>(u: U\n'.repeat(N / 33),
      languages: ['typescript'],
    },
    // Angle-bracket soup: the generics group must not turn `a < b > c` runs into
    // an exponential search.
    { name: 'angle-soup', content: `${'a<'.repeat(N / 4)}b(x): C {\n`, languages: ['typescript'] },
    // Colon soup: the return-type run is bounded and cannot cross `{`.
    { name: 'colon-soup', content: `f(x)${':'.repeat(N / 2)}{\n`, languages: ['typescript'] },
  ];

  for (const { name, content, languages } of ADVERSARIAL) {
    it(`matches '${name}' (${Math.round(content.length / 1000)}KB) within ${BUDGET_MS}ms`, () => {
      for (const language of languages) {
        const c = ctx(content, language);
        const t0 = Date.now();
        primitiveRoleCheck.match(c);
        longSecurityMethod.match(c);
        const elapsed = Date.now() - t0;
        expect(elapsed, `${name} @ ${language} took ${elapsed}ms`).toBeLessThan(BUDGET_MS);
      }
    });
  }
});
