// vibeguard:disable-file VG-RTOS-001
// This file DEFINES the RTOS/interrupt rules; the forbidden-API tokens
// (`malloc(`, `printf(`, `Serial.print(`) appear inside regex sources by design.
//
// VG-EMB 17f EMB-RTOS — interrupt / concurrency rules (languages ['c','cpp']).
//
// THIS BLOCK DISCHARGES 17c's PROOF BURDEN. 17c rejected tree-sitter on the
// claim that structural rules ("a forbidden call INSIDE an ISR body") can be
// written lexically. VG-RTOS-001/002 are the proof: they share
// `collectIsrBlocks`, which uses `extractBlockAfter` (matcher-utils.ts) — a
// linear balanced-brace scan, no parser — to get the ISR body, then bounded
// regexes over it. No expression parser was needed.
//
// VG-RTOS-002 (volatile-leak) is the highest false-positive risk in the family
// (atomics, member access, interrupt-masked sections all resemble leaks), so it
// is deliberately conservative: it flags ONLY a UNIQUE, non-volatile, non-atomic
// FILE-SCOPE scalar that is written in an ISR body and read outside it. Every
// ambiguity (no declaration found, more than one, any `volatile`/`atomic`/
// `const`) resolves to SILENCE — the safe side that keeps samples/embedded/safe
// at zero. confidence `low`.
//
// DROPPED (listing them IS the honest boundary of the lexical approach; see the
// README drop-list):
//   - xTaskCreate stack-size magic number: DROPPED. The stack-depth unit is
//     WORDS on vanilla FreeRTOS and BYTES on ESP-IDF, so any numeric threshold
//     is wrong on some platform — and a security tool that is wrong about a
//     number burns trust out of proportion to the finding.
//   - Hardcoded task priority: DROPPED (universal practice, pure noise).
//   - Mutex acquire-order / priority inversion: DROPPED (needs a lock graph
//     across functions; no lexical fence makes it honest).
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import {
  runRegex,
  indexToPosition,
  isCommentLine,
  extractBlockAfter,
  blankCommentsAndStrings,
  REGEX_INPUT_CAP,
  REGEX_MATCH_LIMIT,
  type ExtractedBlock,
} from '../matcher-utils.js';

/**
 * Calls that must not appear in interrupt context: they allocate, block, or do
 * I/O, any of which can deadlock or corrupt from an ISR.
 *
 * Two exclusions are baked into the shape, not filtered after:
 *  - `\bdelay[ \t]{0,8}\(` does NOT match `delayMicroseconds(` (the next char is
 *    `M`, not whitespace/paren) — busy-wait is legal in an ISR.
 *  - the FreeRTOS names require `[ \t]{0,8}\(` immediately after, which excludes
 *    the CORRECT `…FromISR(` variants (their next char is `F`).
 */
const FORBIDDEN_IN_ISR =
  /\b(?:m|c|re)alloc[ \t]{0,8}\(|(?<![\w.>])free[ \t]{0,8}\(|\bdelay[ \t]{0,8}\(|\b(?:s|f|v)?printf[ \t]{0,8}\(|\bSerial\.(?:print(?:ln|f)?|begin)[ \t]{0,8}\(|\bx(?:QueueSend|QueueReceive|SemaphoreGive|SemaphoreTake|TaskNotify\w{0,20})[ \t]{0,8}\(/g;

/** Scan one extracted ISR body for forbidden calls; report at file positions. */
function scanIsrBody(
  scanText: string,
  block: ExtractedBlock,
  lines: string[],
  language: string | undefined,
  out: RuleMatch[],
): void {
  FORBIDDEN_IN_ISR.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FORBIDDEN_IN_ISR.exec(block.body)) !== null && out.length < REGEX_MATCH_LIMIT) {
    const fileIndex = block.start + m.index;
    const pos = indexToPosition(scanText, fileIndex);
    if (isCommentLine(lines[pos.line - 1] ?? '', language)) continue;
    out.push({
      startLine: pos.line,
      endLine: pos.line,
      startColumn: pos.column,
      endColumn: pos.column + m[0].length,
      evidence: m[0].trim(),
    });
    if (m[0].length === 0) FORBIDDEN_IN_ISR.lastIndex += 1;
  }
}

/**
 * Collect the balanced bodies of every interrupt handler in `scanText`, deduped
 * by start offset. SHARED by VG-RTOS-001 and VG-RTOS-002 so the two cannot drift
 * on what counts as an ISR. `scanText` must already be comment/string-blanked.
 *
 * Three head forms: an AVR `ISR(VECT)`, an ESP32/ESP8266 `IRAM_ATTR`/
 * `ICACHE_RAM_ATTR` handler, and a function named by `attachInterrupt`. For the
 * last, the first `void fn(` may be a forward declaration (extractBlockAfter
 * returns null — see its `;` guard), so we loop to the real definition.
 */
function collectIsrBlocks(scanText: string): ExtractedBlock[] {
  const blocks: ExtractedBlock[] = [];
  const seen = new Set<number>();
  const add = (block: ExtractedBlock | null): void => {
    if (block && !seen.has(block.start)) {
      seen.add(block.start);
      blocks.push(block);
    }
  };

  const directHeads = [
    /(?<![\w.>])ISR[ \t]{0,8}\([ \t]{0,8}\w{1,40}[ \t]{0,8}\)/g,
    /\b(?:IRAM_ATTR|ICACHE_RAM_ATTR)[ \t]{1,8}\w{1,40}[ \t]{0,8}\([^)\n]{0,80}\)/g,
  ];
  for (const re of directHeads) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = re.exec(scanText)) !== null && count < REGEX_MATCH_LIMIT) {
      count += 1;
      add(extractBlockAfter(scanText, m.index + m[0].length));
    }
  }

  const attach = /\battachInterrupt[ \t]{0,8}\([^,;\n]{0,80},[ \t]{0,8}(\w{1,60})[ \t]{0,8},/g;
  let a: RegExpExecArray | null;
  let seenAttach = 0;
  while ((a = attach.exec(scanText)) !== null && seenAttach < REGEX_MATCH_LIMIT) {
    seenAttach += 1;
    const fn = a[1]!; // `\w+` — safe to interpolate.
    const defRe = new RegExp(
      `\\bvoid[ \\t]{1,8}(?:(?:IRAM_ATTR|ICACHE_RAM_ATTR)[ \\t]{1,8})?${fn}[ \\t]{0,8}\\(`,
      'g',
    );
    let def: RegExpExecArray | null;
    while ((def = defRe.exec(scanText)) !== null) {
      const block = extractBlockAfter(scanText, def.index + def[0].length);
      if (block) {
        add(block);
        break;
      }
    }
  }
  return blocks;
}

export const rtosForbiddenApiInIsr: RuleDefinition = {
  ruleId: 'VG-RTOS-001',
  name: 'Forbidden call inside an interrupt handler',
  description:
    'An allocation, blocking, or I/O call (malloc/free/delay/printf/Serial.print, or a non-FromISR FreeRTOS queue/semaphore call) appears inside an ISR / IRAM_ATTR handler / attachInterrupt callback body. From interrupt context these deadlock, re-enter the allocator, or block indefinitely.',
  languages: ['c', 'cpp'],
  category: 'concurrency',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-662'],
  tags: ['embedded', 'rtos', 'isr', 'ai-prone'],
  remediation: {
    why: 'ISRs run with interrupts disabled and no scheduler; malloc/printf/blocking calls can deadlock the allocator or the RTOS. AI-generated handlers routinely Serial.print or delay inside an ISR.',
    how: 'Do the minimum in the ISR — set a volatile flag or use the *FromISR() API — and defer the real work to a task. Move Serial/printf/malloc out of interrupt context.',
    exampleFix: 'void IRAM_ATTR onTick() { flag = true; }  // handle in loop()',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    // Blank comments/strings so a `/* Serial.print old *\/` inside a handler is
    // not flagged; length-preserving so lines still map to the original.
    const scanText = blankCommentsAndStrings(raw);
    const out: RuleMatch[] = [];
    for (const block of collectIsrBlocks(scanText)) {
      scanIsrBody(scanText, block, ctx.lines, ctx.language, out);
    }
    return out;
  },
};

/** Scalar type keywords a file-scope shared variable is declared with. */
const SCALAR_TYPE =
  '(?:bool|char|short|int|long|float|double|u?int(?:8|16|32|64)_t|size_t|word|byte)';

/** Names declared locally inside an ISR body (so they are not shared state). */
function localDeclNames(body: string): Set<string> {
  const names = new Set<string>();
  // The delimiter class INCLUDES `\n`: a local declaration usually sits at the
  // start of its own line, and without `\n` here that form is missed — so a
  // body-local that shadows a same-named file-scope global would be treated as a
  // write to the global and falsely flag it. Adding `\n` can only shrink the
  // finding set (more names recognised as local), which is the safe direction.
  const re = new RegExp(
    `(?:^|[;{(,\\n])[ \\t]*(?:(?:static|const|volatile|unsigned|signed|register|auto)[ \\t]+)*${SCALAR_TYPE}[ \\t]+\\*?[ \\t]*([A-Za-z_]\\w{0,40})`,
    'g',
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) names.add(m[1]!);
  return names;
}

export const rtosVolatileLeak: RuleDefinition = {
  ruleId: 'VG-RTOS-002',
  name: 'Shared ISR variable missing volatile',
  description:
    'A plain (non-volatile, non-atomic) file-scope scalar is written inside an interrupt handler and read outside it. Without volatile the compiler may cache the value in a register, so the non-ISR reader never sees the ISR\'s update. SAME-FILE ONLY; anything the compiler could prove atomic or that is guarded is out of scope.',
  languages: ['c', 'cpp'],
  category: 'concurrency',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-457', 'CWE-662'],
  tags: ['embedded', 'rtos', 'isr'],
  remediation: {
    why: 'A variable shared between an ISR and the main loop must be volatile (and, for multi-byte access, protected) or the reader can spin on a stale, register-cached copy forever.',
    how: 'Mark the shared variable volatile. For values wider than one atomic access, also guard reads/writes (noInterrupts()/interrupts() or a critical section).',
    exampleFix: 'volatile bool flag = false;',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    const scanText = blankCommentsAndStrings(raw);
    const blocks = collectIsrBlocks(scanText);
    if (blocks.length === 0) return [];

    const isrRanges = blocks.map((b): [number, number] => [b.start, b.end]);
    const inIsr = (idx: number): boolean => isrRanges.some(([s, e]) => idx >= s && idx < e);

    // Bare-identifier writes inside any ISR body (member/array writes are
    // excluded by the lookbehind and by requiring `name` then an assignment).
    const written = new Set<string>();
    const WRITE = /(?<![\w.>])([A-Za-z_]\w{0,40})[ \t]{0,8}(?:=[^=]|\+\+|--|[+\-*/%|&^]=)/g;
    for (const b of blocks) {
      const locals = localDeclNames(b.body);
      WRITE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = WRITE.exec(b.body)) !== null) {
        const name = m[1]!;
        if (!locals.has(name)) written.add(name);
      }
    }

    const out: RuleMatch[] = [];
    for (const name of written) {
      // A file-scope (column-0) scalar declaration of `name`. If none, it is a
      // local / struct member / extern — out of scope, stay silent.
      const declRe = new RegExp(
        `^(?:static[ \\t]+|extern[ \\t]+)?(?:(?:unsigned|signed)[ \\t]+)?(?:(?:volatile|const|register|_Atomic)[ \\t]+)*${SCALAR_TYPE}[ \\t]+\\*?[ \\t]*${name}[ \\t]*[=;,\\[]`,
        'gm',
      );
      const decls: RegExpExecArray[] = [];
      let d: RegExpExecArray | null;
      while ((d = declRe.exec(scanText)) !== null) decls.push(d);
      // Exactly ONE declaration — ambiguity (0 or many) is the silent side.
      if (decls.length !== 1) continue;
      const decl = decls[0]!;
      // Already protected → not a leak.
      if (/\b(?:volatile|const|register|extern|_Atomic)\b|atomic/i.test(decl[0])) continue;

      // A use outside every ISR body, beyond the declaration itself.
      const useRe = new RegExp(`\\b${name}\\b`, 'g');
      let outsideUses = 0;
      let u: RegExpExecArray | null;
      while ((u = useRe.exec(scanText)) !== null) {
        if (!inIsr(u.index)) outsideUses += 1;
      }
      // The declaration is one outside use; a genuine reader is a second.
      if (outsideUses < 2) continue;

      const pos = indexToPosition(scanText, decl.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + decl[0].length,
        evidence: decl[0].trim(),
      });
    }
    return out;
  },
};

export const rtosODirectNoSync: RuleDefinition = {
  ruleId: 'VG-RTOS-004',
  name: 'O_DIRECT open without O_SYNC (NuttX)',
  description:
    'open() with O_DIRECT but no O_SYNC/O_DSYNC bypasses the page cache without guaranteeing the write reaches storage — data loss on power cut, common on battery devices.',
  languages: ['c', 'cpp'],
  category: 'concurrency',
  severity: 'low',
  defaultConfidence: 'low',
  cwe: ['CWE-662'],
  tags: ['embedded', 'nuttx'],
  remediation: {
    why: 'O_DIRECT skips the cache but does not force durability; without O_SYNC a write can be lost if power is cut before the device flushes.',
    how: 'Add O_SYNC (or O_DSYNC) to the open flags, or fsync() after the writes that must survive a power loss.',
  },
  // The match window extends PAST O_DIRECT to the end of the flags so the
  // post-filter can see a TRAILING O_SYNC (`open(p, O_DIRECT | O_SYNC)`) — the
  // common ordering. Without the trailing span the evidence stopped at O_DIRECT
  // and the filter never saw the sync flag, firing on correctly-synced code.
  match: (ctx) =>
    runRegex(ctx.content, /(?<![\w.>])open[ \t]{0,8}\([^;\n]{0,160}\bO_DIRECT\b[^;\n]{0,80}/g, {
      skipCommentLines: true,
      language: ctx.language,
    }).filter((m) => !/O_SYNC|O_DSYNC/.test(m.evidence)),
};

export const rtosRules: RuleDefinition[] = [
  rtosForbiddenApiInIsr,
  rtosVolatileLeak,
  rtosODirectNoSync,
];
