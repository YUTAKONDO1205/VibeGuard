// Lexical layer for LLVM textual IR.
//
// The fingerprint reads `.ll` text rather than in-memory IR, because it has to
// compare output from four separate compiler invocations and the text is the
// only representation all four share. That choice is a real limitation and is
// written down in the README rather than left to be discovered: this is a
// textual normaliser over IR, not an IR-semantics normaliser.

/** One token: a name, a keyword, a literal, or a single punctuation mark. */
const TOKEN_RE = new RegExp(
  [
    '[%@]"(?:[^"\\\\]|\\\\.)*"', // quoted local or global name
    '[%@][-a-zA-Z$._0-9]+', // local or global name
    '!"(?:[^"\\\\]|\\\\.)*"', // quoted metadata string
    '![-a-zA-Z$._0-9]+', // metadata name or numeric metadata reference
    '"(?:[^"\\\\]|\\\\.)*"', // string literal
    '#[0-9]+', // attribute-group reference
    '0x[0-9A-Fa-f]+', // hex literal
    '[-+]?[0-9]+(?:\\.[0-9]+)?(?:[eE][-+]?[0-9]+)?', // numeric literal
    '[A-Za-z_$.][-A-Za-z_$.0-9]*', // keyword, opcode, or type
    '[(){}\\[\\]<>,*=!]', // punctuation
    '\\S', // anything else, one character at a time
  ].join('|'),
  'g',
);

/**
 * Remove a `;` comment, respecting string literals. LLVM writes `; preds = ...`
 * after block labels and `; Function Attrs: ...` above definitions; both are
 * output decoration and neither is part of the program.
 */
export function stripComment(line) {
  let inString = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (c === '\\' && inString) {
      i += 1;
      continue;
    }
    if (c === '"') inString = !inString;
    else if (c === ';' && !inString) return line.slice(0, i);
  }
  return line;
}

export function tokenize(line) {
  const out = stripComment(line).match(TOKEN_RE);
  return out === null ? [] : out;
}

export const isLocal = (t) => typeof t === 'string' && t.length > 1 && t[0] === '%';
export const isGlobal = (t) => typeof t === 'string' && t.length > 1 && t[0] === '@';
export const isAttrGroup = (t) => typeof t === 'string' && /^#[0-9]+$/.test(t);
/** `!12` — a reference to a numbered metadata node. */
export const isMetaRef = (t) => typeof t === 'string' && /^![0-9]+$/.test(t);
/** `!dbg`, `!tbaa`, `!DIExpression` — a metadata name. */
export const isMetaName = (t) => typeof t === 'string' && /^![A-Za-z_$.][-A-Za-z_$.0-9]*$/.test(t);

/** Strip the sigil from `%foo` / `@foo`, and the quotes from `%"foo bar"`. */
export function bareName(t) {
  const body = t.slice(1);
  return body.startsWith('"') ? body.slice(1, -1) : body;
}

/**
 * Indices of tokens that name a basic block rather than a value.
 *
 * Two rules cover every terminator LLVM can print: a block reference is either
 * the token straight after the keyword `label`, or the second element of a phi
 * `[ value, block ]` pair. Getting this wrong in the permissive direction would
 * merge the value and label namespaces, which LLVM keeps separate.
 */
export function labelOperandIndices(tokens) {
  const idx = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i] === 'label' && i + 1 < tokens.length && isLocal(tokens[i + 1])) idx.push(i + 1);
  }
  if (tokens[0] === 'phi') {
    let i = 0;
    while (i < tokens.length) {
      if (tokens[i] !== '[') {
        i += 1;
        continue;
      }
      const close = tokens.indexOf(']', i);
      if (close === -1) break;
      // The last token before `]` is the incoming block.
      if (isLocal(tokens[close - 1]) && !idx.includes(close - 1)) idx.push(close - 1);
      i = close + 1;
    }
  }
  return idx;
}
