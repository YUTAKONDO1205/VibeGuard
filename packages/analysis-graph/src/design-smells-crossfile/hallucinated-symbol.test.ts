import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { isDesignSmellFinding, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { analyzeProject } from '../project.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);

const aisc2In = async (dir: string): Promise<DesignSmellFinding[]> => {
  const result = await analyzeProject(dir);
  return result.findings.filter(
    (f): f is DesignSmellFinding => isDesignSmellFinding(f) && f.ruleId === 'VG-AISC-002',
  );
};

describe('VG-AISC-002 — positive case', () => {
  it('reports an undeclared member of a family the headers do declare', async () => {
    const findings = await aisc2In(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.description).toContain('cxd56_gpio_toggle');
    expect(findings[0]!.filePath).toBe('main.c');
  });

  it('names the family and its real members, because the claim is comparative', async () => {
    // Without the siblings the finding degenerates to "we could not find this",
    // which is the weak formulation this rule was built to avoid making.
    const [finding] = await aisc2In(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(finding!.description).toContain('cxd56_gpio_*');
    expect(finding!.description).toContain('cxd56_gpio_write');
    expect(finding!.evidence?.join(' ')).toContain('cxd56_gpio_read');
  });

  it('caps confidence at medium and scopes to the symbol', async () => {
    const [finding] = await aisc2In(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(finding!.confidence).toBe('medium');
    expect(finding!.severity).toBe('high');
    expect(finding!.scope).toBe('symbol');
  });

  it('points at the header that declares the real family', async () => {
    const [finding] = await aisc2In(sample('crossfile-fixtures/embedded-hallucinated'));
    expect((finding!.relatedLocations ?? []).map((l) => l.filePath)).toContain('sdk/cxd56_gpio.h');
  });
});

describe('VG-AISC-002 — the falsification corpus', () => {
  it('stays silent on real API calls and on the standard library', async () => {
    // THE test for this rule. `memset`, `memcpy`, `snprintf`, and `printf` are
    // declared only in system headers that never resolve. The naive "declared
    // nowhere" formulation reports all four on correct firmware; the
    // known-namespace formulation must report none.
    expect(await aisc2In(sample('crossfile-fixtures/embedded-real-api'))).toEqual([]);
  });

  it('stays silent when there is no C in the project at all', async () => {
    expect(await aisc2In(sample('crossfile-vulnerable'))).toEqual([]);
  });

  it('stays silent on the other embedded corpora', async () => {
    // embedded-wired and embedded-unintegrated exist for VG-AISC-003. Neither
    // declares an API family with three members, so 002 has no namespace to
    // reason about and must not speak.
    expect(await aisc2In(sample('crossfile-fixtures/embedded-wired'))).toEqual([]);
    expect(await aisc2In(sample('crossfile-fixtures/embedded-unintegrated'))).toEqual([]);
  });

  it('does not fire on the safe TS corpus', async () => {
    expect(await aisc2In(sample('crossfile-safe'))).toEqual([]);
  });
});

describe('VG-AISC-002 — rules do not interfere with each other', () => {
  it('AISC-002 and AISC-003 stay on their own corpora', async () => {
    const hallucinated = await analyzeProject(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(hallucinated.findings.map((f) => f.ruleId)).toEqual(['VG-AISC-002']);

    const unintegrated = await analyzeProject(sample('crossfile-fixtures/embedded-unintegrated'));
    expect(unintegrated.findings.map((f) => f.ruleId)).toEqual(['VG-AISC-003']);
  });
});

describe('VG-AISC-002 — partially vendored SDK (regression)', () => {
  it('does not accuse a real function from an unscanned sibling family', async () => {
    // The normal shape of embedded work: part of the SDK vendored (quoted,
    // scanned), the rest on the include path (angled, unscanned). Accepting any
    // known ANCESTOR prefix as evidence made the vendored `cxd56_gpio_*` family
    // vouch for the whole `cxd56` namespace, and every real call into a
    // different `cxd56_*` family was then accused of not existing.
    expect(await aisc2In(sample('crossfile-fixtures/embedded-partial-sdk'))).toEqual([]);
  });

  it('still fires when the immediate family IS the known one', async () => {
    // The distinction that makes the rule work: `cxd56_gpio_toggle`'s immediate
    // family is `cxd56_gpio`, whose header WAS read, so its absence is evidence.
    const findings = await aisc2In(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(findings).toHaveLength(1);
  });
});

describe('VG-AISC-002 — a namespace cannot be built out of call sites (corpus repair)', () => {
  it('stays silent on a system library the project only ever CALLS', async () => {
    // ★ THE REGRESSION THAT REAL CODE FOUND. Before the `PROTOTYPE` guard,
    // `return SSL_get_cipher_name(conn);` matched as a declaration — `return`
    // occupies the type slot and the call's `)` is followed by `;` — so three
    // such lines conjured the `SSL_*` namespace out of nothing, and every other
    // (entirely real) OpenSSL call in the file was reported as hallucinated.
    //
    // This was not hypothetical: a sweep of paper_data/corpus1k produced 23
    // findings across 4 repositories and every one was this shape.
    const findings = await aisc2In(sample('crossfile-fixtures/smell-aisc002-neg-return-call'));
    expect(findings).toEqual([]);
  });

  it('a real prototype still establishes the namespace, so the guard is not a mute button', async () => {
    // The falsifying half. If the fix had simply stopped PROTOTYPE matching, the
    // test above would pass for the wrong reason and the rule would be dead. The
    // shipped positive fixture declares its family in a HEADER, and must still fire.
    const findings = await aisc2In(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.description).toContain('cxd56_gpio_toggle');
  });
});
