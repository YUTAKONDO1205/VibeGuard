#!/usr/bin/env node
// A deliberately naive lexical scanner. It exists to PRODUCE the input the AST
// gate consumes, and it is naive on purpose: it matches over the raw text with
// no comment or string blanking, so it emits exactly the false positives the
// gate has to reject. A scanner that already blanked them would make the
// Rejected class untestable.
//
// Note the honest difference from what VibeGuard ships: the shipped C rules in
// packages/rules/src/rules/lang-c.ts DO blank comments and strings
// (`blankCommentsAndStrings`), so in the shipped pipeline the Rejected class
// arrives from the cases blanking cannot reach — a declaration that is never
// called, an identifier inside `#if 0`, a macro body. Those fixtures are in the
// set for that reason.
//
// Output: interfaces.md §2 findings, plus `where.line`, `where.column` and
// `match`, which §2 does not define. See README.md, "Schema gaps reported
// upward".
//
//   node lexscan.mjs <file.c> [<file.c> ...] --root <dir> > findings.json

import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const RULES = [
  {
    id: 'VG-CEXEC-001',
    severity: 'high',
    title: 'A shell is invoked from C',
    // Identifier-only, not `system\s*\(`: the address-taken form (`= system;`)
    // and the macro-alias form (`#define SHELL system`) have no paren after
    // them, and both are shapes the gate is supposed to refine rather than
    // shapes the scanner should miss.
    re: /(?<![\w.>])(?:system|popen)\b/g,
  },
  {
    id: 'VG-CEXEC-002',
    severity: 'high',
    title: 'An exec-family call from C',
    re: /(?<![\w.>])(?:execl|execlp|execle|execv|execvp|execvpe)\b/g,
  },
  {
    id: 'VG-MEM-006',
    severity: 'medium',
    title: 'A buffer cleared with a removable memset',
    re: /(?<![\w.>])memset[ \t]{0,8}\(/g,
  },
];

const argv = process.argv.slice(2);
let root = process.cwd();
const files = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--root') {
    root = resolve(argv[++i]);
  } else {
    files.push(argv[i]);
  }
}

function lineColOf(text, index) {
  let line = 1;
  let lastNl = -1;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lastNl = i;
    }
  }
  return { line, column: index - lastNl };
}

const findings = [];
for (const file of files) {
  const abs = resolve(file);
  const text = readFileSync(abs, 'utf8');
  const rel = relative(root, abs).split('\\').join('/');
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      const { line, column } = lineColOf(text, m.index);
      findings.push({
        id: rule.id,
        severity: rule.severity,
        title: rule.title,
        detail: `lexical match ${JSON.stringify(m[0])} at ${rel}:${line}`,
        where: { kind: 'source', path: rel, unit: null, pass: null, line, column },
        match: m[0],
      });
    }
  }
}

findings.sort((a, b) =>
  a.where.path === b.where.path
    ? a.where.line - b.where.line || a.where.column - b.where.column || a.id.localeCompare(b.id)
    : a.where.path.localeCompare(b.where.path),
);

process.stdout.write(JSON.stringify({ root: '.', findings }, null, 2) + '\n');
