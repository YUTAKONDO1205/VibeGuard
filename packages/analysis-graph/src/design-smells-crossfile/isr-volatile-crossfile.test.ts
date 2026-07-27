import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import {
  designSmellLocationsAgree,
  isDesignSmellFinding,
  type DesignSmellFinding,
} from '@vibeguard/findings-schema';
import { createBudget } from '../budget.js';
import { toSourceFile } from '../dependency-graph/index.js';
import { analyzeProject, buildProjectIndex } from '../project.js';
import type { CrossFileFinding } from '../types.js';
import { isrVolatileCrossFile } from './isr-volatile-crossfile.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);

const rtos3In = async (dir: string): Promise<DesignSmellFinding[]> => {
  const result = await analyzeProject(dir);
  return result.findings.filter(
    (f): f is DesignSmellFinding => isDesignSmellFinding(f) && f.ruleId === 'VG-RTOS-003',
  );
};

/**
 * Run the rule over files that exist only in the test.
 *
 * The corpus fixtures are the contract and stay on disk; this is for the shapes
 * that are about the MECHANISM (which handler heads are recognised, what a
 * shadowing local does, how long an adversarial line takes) and would be noise
 * in `samples/`, which doubles as documentation.
 */
const inMemory = (files: { path: string; src: string }[]): CrossFileFinding[] => {
  const budget = createBudget({});
  const sources = files.map((f) =>
    toSourceFile(f.path, f.path.endsWith('.ino') ? 'cpp' : 'c', f.src),
  );
  const project = buildProjectIndex('/project', sources, budget);
  return isrVolatileCrossFile.analyze({ project, budget });
};

/** The positive case's three files, so a variant can change exactly one thing. */
const SHARED_H = [
  '#ifndef SHARED_H',
  '#define SHARED_H',
  '#include <stdint.h>',
  'extern uint32_t tick_count;',
  '#endif',
].join('\n');

const ISR_C = ['#include "shared.h"', 'uint32_t tick_count = 0;', 'ISR(TIMER1_COMPA_vect)', '{', '  tick_count++;', '}'].join(
  '\n',
);

const MAIN_C = [
  '#include "shared.h"',
  'int main(void)',
  '{',
  '  uint32_t last = 0;',
  '  for (;;) {',
  '    if (tick_count != last) { last = tick_count; }',
  '  }',
  '  return 0;',
  '}',
].join('\n');

describe('VG-RTOS-003 — positive case', () => {
  it('reports the handler/reader split VG-RTOS-002 cannot see', async () => {
    const findings = await rtos3In(sample('crossfile-fixtures/embedded-volatile-missing'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.description).toContain('tick_count');
  });

  it('files the finding on the header declaration, because that is where the fix goes', async () => {
    const [finding] = await rtos3In(sample('crossfile-fixtures/embedded-volatile-missing'));
    expect(finding!.filePath).toBe('shared.h');
    expect(finding!.startLine).toBe(7);
    expect(designSmellLocationsAgree(finding!)).toBe(true);
  });

  it('carries both sides of the claim as related locations', async () => {
    // Without them the finding says "this declaration has no volatile", which is
    // true of most declarations. The claim is the RELATIONSHIP.
    const [finding] = await rtos3In(sample('crossfile-fixtures/embedded-volatile-missing'));
    const paths = (finding!.relatedLocations ?? []).map((l) => l.filePath);
    expect(paths).toContain('isr.c');
    expect(paths).toContain('main.c');
  });

  it('caps confidence at medium and scopes to the module', async () => {
    const [finding] = await rtos3In(sample('crossfile-fixtures/embedded-volatile-missing'));
    expect(finding!.severity).toBe('medium');
    expect(finding!.confidence).toBe('medium');
    expect(finding!.scope).toBe('module');
  });

  it('offers the fixed declaration rather than generic advice', async () => {
    const [finding] = await rtos3In(sample('crossfile-fixtures/embedded-volatile-missing'));
    expect(finding!.remediation?.exampleFix).toBe('extern volatile uint32_t tick_count;');
  });

  it('measures the declaring header fan-in instead of asserting a number', async () => {
    // Both .c files include shared.h, so the declaration is visible to two
    // translation units. A hardcoded metric would say this without measuring it.
    const [finding] = await rtos3In(sample('crossfile-fixtures/embedded-volatile-missing'));
    expect(finding!.metrics?.fanIn).toBe(2);
  });
});

describe('VG-RTOS-003 — the falsification corpus', () => {
  it('stays silent when the declaration is already volatile', async () => {
    expect(await rtos3In(sample('crossfile-fixtures/embedded-volatile-declared'))).toEqual([]);
  });

  it('stays silent when any file declares the name static', async () => {
    // The `static` in logger.c is a different object with the same name, and
    // nothing lexical can prove it. Silence is the price of that guard.
    expect(await rtos3In(sample('crossfile-fixtures/embedded-volatile-static'))).toEqual([]);
  });

  it('stays silent when two project headers declare the name', async () => {
    expect(await rtos3In(sample('crossfile-fixtures/embedded-volatile-two-decls'))).toEqual([]);
  });

  it('stays silent when the qualifier is behind a typedef', async () => {
    // THE test for the type set. The code is correct — reg_t IS volatile — and
    // the declaration line contains no `volatile` token to prove it.
    expect(await rtos3In(sample('crossfile-fixtures/embedded-volatile-typedef'))).toEqual([]);
  });

  it('stays silent when the declaration lives outside the scan', async () => {
    expect(await rtos3In(sample('crossfile-fixtures/embedded-volatile-angled'))).toEqual([]);
  });

  it('stays silent on the other embedded corpora', async () => {
    expect(await rtos3In(sample('crossfile-fixtures/embedded-hallucinated'))).toEqual([]);
    expect(await rtos3In(sample('crossfile-fixtures/embedded-real-api'))).toEqual([]);
    expect(await rtos3In(sample('crossfile-fixtures/embedded-partial-sdk'))).toEqual([]);
    expect(await rtos3In(sample('crossfile-fixtures/embedded-wired'))).toEqual([]);
    expect(await rtos3In(sample('crossfile-fixtures/embedded-unintegrated'))).toEqual([]);
  });

  it('does not fire on the embedded corpora the single-file rules own', async () => {
    // `samples/embedded` is the VG-EMB / VG-RTOS corpus and is full of real
    // interrupt handlers — the highest-risk population for this rule's false
    // positives, and the one the E7 pin (vuln=26 / safe=0) is written against.
    // The safe half must stay silent because it is correct; the vulnerable half
    // must stay silent because its `volatile` defect is SAME-FILE, which is
    // VG-RTOS-002's and not this rule's.
    expect(await rtos3In(sample('embedded/safe'))).toEqual([]);
    expect(await rtos3In(sample('embedded/vulnerable'))).toEqual([]);
  });

  it('does not fire on the other safe corpora', async () => {
    expect(await rtos3In(sample('safe'))).toEqual([]);
    expect(await rtos3In(sample('design-safe'))).toEqual([]);
    expect(await rtos3In(sample('proto-safe'))).toEqual([]);
  });

  it('does not fire on the safe TS corpus', async () => {
    // The project-level language gate should skip the rule entirely here; the
    // per-file filter is what keeps it honest in a polyglot repository.
    expect(await rtos3In(sample('crossfile-safe'))).toEqual([]);
    expect(await rtos3In(sample('crossfile-vulnerable'))).toEqual([]);
  });
});

describe('VG-RTOS-003 — rules do not interfere with each other', () => {
  it('is the only rule that speaks on its own corpus', async () => {
    const result = await analyzeProject(sample('crossfile-fixtures/embedded-volatile-missing'));
    expect(result.findings.map((f) => f.ruleId)).toEqual(['VG-RTOS-003']);
  });

  it('adds nothing to the corpora the other cross-file rules own', async () => {
    const hallucinated = await analyzeProject(sample('crossfile-fixtures/embedded-hallucinated'));
    expect(hallucinated.findings.map((f) => f.ruleId)).toEqual(['VG-AISC-002']);
    const unintegrated = await analyzeProject(sample('crossfile-fixtures/embedded-unintegrated'));
    expect(unintegrated.findings.map((f) => f.ruleId)).toEqual(['VG-AISC-003']);
  });
});

describe('VG-RTOS-003 — handler head forms', () => {
  // PIN for the copy of `collectIsrBlocks` taken from
  // packages/rules/src/rules/embedded-rtos.ts. If VG-RTOS-002 grows a fourth
  // head form and this copy does not, these assertions are what says so.
  it('recognises the AVR ISR(VECT) form', () => {
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: MAIN_C },
    ])).toHaveLength(1);
  });

  it('recognises an IRAM_ATTR handler', () => {
    const esp = [
      '#include "shared.h"',
      'uint32_t tick_count = 0;',
      'void IRAM_ATTR on_tick(void)',
      '{',
      '  tick_count++;',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: esp },
      { path: 'main.c', src: MAIN_C },
    ])).toHaveLength(1);
  });

  it('recognises a function registered through attachInterrupt', () => {
    const arduino = [
      '#include "shared.h"',
      'uint32_t tick_count = 0;',
      'void on_edge(void);',
      'void setup(void) { attachInterrupt(0, on_edge, 1); }',
      'void on_edge(void)',
      '{',
      '  tick_count++;',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.ino', src: arduino },
      { path: 'main.c', src: MAIN_C },
    ])).toHaveLength(1);
  });

  it('says nothing when the write is not inside a handler at all', () => {
    const plain = [
      '#include "shared.h"',
      'uint32_t tick_count = 0;',
      'void bump(void)',
      '{',
      '  tick_count++;',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: plain },
      { path: 'main.c', src: MAIN_C },
    ])).toEqual([]);
  });
});

describe('VG-RTOS-003 — layouts it must still recognise', () => {
  // The positive fixture is one arrangement of three files. These are the other
  // arrangements the same defect arrives in; a rule that only fired on the
  // fixture's exact shape would be a fixture test, not a rule.
  it('fires when the definition lives in a third file', () => {
    const isrOnly = [
      '#include "shared.h"',
      'ISR(TIMER1_COMPA_vect)',
      '{',
      '  tick_count++;',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'shared.c', src: '#include "shared.h"\nuint32_t tick_count = 0;' },
      { path: 'isr.c', src: isrOnly },
      { path: 'main.c', src: MAIN_C },
    ])).toHaveLength(1);
  });

  it('fires when the reader is also the file that defines the variable', () => {
    const isrOnly = [
      '#include "shared.h"',
      'ISR(TIMER1_COMPA_vect)',
      '{',
      '  tick_count++;',
      '}',
    ].join('\n');
    const definingReader = ['uint32_t tick_count = 0;', MAIN_C].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: isrOnly },
      { path: 'main.c', src: definingReader },
    ])).toHaveLength(1);
  });

  it('fires through a header reached by a subdirectory path', () => {
    const nested = ISR_C.replace('"shared.h"', '"inc/shared.h"');
    const nestedMain = MAIN_C.replace('"shared.h"', '"inc/shared.h"');
    expect(inMemory([
      { path: 'inc/shared.h', src: SHARED_H },
      { path: 'isr.c', src: nested },
      { path: 'main.c', src: nestedMain },
    ])).toHaveLength(1);
  });

  it('says nothing when the only other reader is itself an interrupt handler', () => {
    // Two handlers sharing a variable is a different (and harder) problem than
    // a handler and ordinary code; `volatile` is not the whole answer to it.
    const otherIsr = [
      '#include "shared.h"',
      'ISR(TIMER2_COMPA_vect)',
      '{',
      '  if (tick_count > 10) { return; }',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: ISR_C },
      { path: 'other.c', src: otherIsr },
    ])).toEqual([]);
  });
});

describe('VG-RTOS-003 — identity guards', () => {
  it('hands the same-file case to VG-RTOS-002 instead of reporting it twice', () => {
    // isr.c now reads the variable outside the handler, which is exactly what
    // the single-file rule fires on. Two findings for one defect, filed in two
    // different files, is worse than one.
    const alsoReads = [ISR_C, 'int isr_last(void) { return (int)tick_count; }'].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: alsoReads },
      { path: 'main.c', src: MAIN_C },
    ])).toEqual([]);
  });

  it('says nothing when the reader has a local of the same name', () => {
    const shadow = [
      '#include "shared.h"',
      'int report(void)',
      '{',
      '  uint32_t tick_count = 0;',
      '  return (int)tick_count;',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: shadow },
    ])).toEqual([]);
  });

  it('says nothing when the reader shadows the name with a C++ `auto` local', () => {
    const shadow = [
      '#include "shared.h"',
      'int report(void)',
      '{',
      '  auto tick_count = 0;',
      '  return (int)tick_count;',
      '}',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: shadow },
    ])).toEqual([]);
  });

  it('says nothing when the reader never includes the declaring header', () => {
    const unrelated = MAIN_C.replace('#include "shared.h"', '#include <stdio.h>');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: unrelated },
    ])).toEqual([]);
  });

  it('says nothing when a quoted include in the closure did not resolve', () => {
    // A missing PROJECT header is where a second declaration would be hiding, so
    // the "exactly one declaration" test would be answering a question about a
    // tree it has not fully seen.
    const dangling = ['#include "board/pins.h"', MAIN_C].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: SHARED_H },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: dangling },
    ])).toEqual([]);
  });

  it('says nothing when the declaration is a member of a flush-left C++ class', () => {
    // Column 0 is not the same question as file scope. VG-RTOS-002 approximates
    // one with the other; on C++ that approximation names the wrong object.
    const classHeader = [
      '#ifndef SHARED_H',
      '#define SHARED_H',
      '#include <stdint.h>',
      'class Board {',
      'public:',
      'uint32_t tick_count;',
      '};',
      '#endif',
    ].join('\n');
    expect(inMemory([
      { path: 'shared.h', src: classHeader },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: MAIN_C },
    ])).toEqual([]);
  });

  it('says nothing when the shared variable is a pointer', () => {
    // `volatile uint32_t *p` and `uint32_t *volatile p` qualify different
    // things, and the declaration text does not say which one was meant.
    const ptrHeader = SHARED_H.replace(
      'extern uint32_t tick_count;',
      'extern uint32_t *tick_count;',
    );
    const ptrIsr = ISR_C.replace('uint32_t tick_count = 0;', 'uint32_t *tick_count = 0;');
    expect(inMemory([
      { path: 'shared.h', src: ptrHeader },
      { path: 'isr.c', src: ptrIsr },
      { path: 'main.c', src: MAIN_C },
    ])).toEqual([]);
  });

  it('says nothing when the qualifier sits on the line above the declaration', () => {
    const wrapped = SHARED_H.replace(
      'extern uint32_t tick_count;',
      'extern volatile\nuint32_t tick_count;',
    );
    expect(inMemory([
      { path: 'shared.h', src: wrapped },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: MAIN_C },
    ])).toEqual([]);
  });

  it('says nothing when the declaration is only in a .c file', () => {
    // No header declaration means nothing states the variable is shared, and a
    // file-local global written by a handler is not this finding.
    const noHeader = ['#ifndef SHARED_H', '#define SHARED_H', '#include <stdint.h>', '#endif'].join(
      '\n',
    );
    expect(inMemory([
      { path: 'shared.h', src: noHeader },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: MAIN_C },
    ])).toEqual([]);
  });
});

describe('VG-RTOS-003 — bounded work on adversarial input', () => {
  /**
   * Cross-file rules do NOT run inside `runRegex`, so the per-rule deadline and
   * the D3 CI check (which walks the core rule catalog) never see them. The
   * 3-second contract still applies, so it is asserted here directly.
   */
  it('finishes a pathological handler body well inside the 3s contract', () => {
    // Every ingredient the patterns backtrack on, repeated: qualifier runs the
    // declaration pattern must try four at a time, assignment chains the write
    // pattern scans, and identifiers that ALMOST end in `_t`.
    //
    // 250 repetitions is ~16.5KB, deliberately just under `extractBlockAfter`'s
    // 20,000-character body cap. Past that the handler body is not extracted at
    // all and the rule falls silent — which is correct, and which would make
    // this test pass for the wrong reason.
    const noise = 'unsigned long const volatile static extern signed short tick_coun ';
    const longLine = `  ${noise.repeat(250)}tick_count = 1;`;
    const heavyIsr = [
      '#include "shared.h"',
      'uint32_t tick_count = 0;',
      'ISR(TIMER1_COMPA_vect)',
      '{',
      longLine,
      '}',
    ].join('\n');
    const heavyHeader = [
      '#ifndef SHARED_H',
      '#define SHARED_H',
      '#include <stdint.h>',
      `${'extern uint32_t pad_x;\n'.repeat(500)}`,
      'extern uint32_t tick_count;',
      '#endif',
    ].join('\n');

    const started = Date.now();
    const findings = inMemory([
      { path: 'shared.h', src: heavyHeader },
      { path: 'isr.c', src: heavyIsr },
      { path: 'main.c', src: MAIN_C },
    ]);
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(3_000);
    // And it still reaches the right answer rather than bailing out.
    expect(findings).toHaveLength(1);
  });

  it('finishes a long unterminated declaration line without blowing up', () => {
    const runaway = `extern ${'unsigned '.repeat(6_000)}uint32_t tick_count`;
    const started = Date.now();
    inMemory([
      { path: 'shared.h', src: [SHARED_H, runaway].join('\n') },
      { path: 'isr.c', src: ISR_C },
      { path: 'main.c', src: MAIN_C },
    ]);
    expect(Date.now() - started).toBeLessThan(3_000);
  });
});
