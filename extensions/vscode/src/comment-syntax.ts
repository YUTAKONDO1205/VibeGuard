/**
 * How to write a comment in one language, for the suppression Quick Fix.
 *
 * The suppression PARSER does not need this — `PRAGMA_RE` in analyzer-core
 * scans raw line text and does not care what wraps the directive, which is why
 * a block comment works as well as a line comment. This table exists for the
 * other half of the job: the Quick Fix WRITES into the user's file, so whatever
 * it inserts has to leave the file parsing as that language afterwards.
 *
 * The rule this replaces was "`#` for nine languages, `//` for everything
 * else", with the provider registered on `scheme: file` — every file type.
 * Several VibeGuard rules are language-agnostic (`VG-CRYPTO-003` matches an
 * `http://` URL in any text), so findings do appear in JSON, CSS, HTML and
 * PowerShell, and the fallback offered `//` for all of them. Accepting the fix
 * in a `.json` file left a document `JSON.parse` rejects: the suppression
 * worked and the config stopped loading.
 *
 * Kept in its own module, free of any `vscode` import, so the choice is
 * testable without an editor host.
 */
export interface CommentStyle {
  /** Inserted as `<token> vibeguard:disable-next-line …`. */
  line?: string;
  /** Inserted as `<open> vibeguard:disable-next-line … <close>`. */
  block?: readonly [open: string, close: string];
}

export const COMMENT_STYLES: Readonly<Record<string, CommentStyle>> = {
  // `#` line comments.
  python: { line: '#' },
  ruby: { line: '#' },
  shellscript: { line: '#' },
  powershell: { line: '#', block: ['<#', '#>'] },
  perl: { line: '#' },
  r: { line: '#' },
  yaml: { line: '#' },
  dockerfile: { line: '#' },
  makefile: { line: '#' },
  toml: { line: '#' },
  properties: { line: '#' },

  // `//` line comments.
  javascript: { line: '//', block: ['/*', '*/'] },
  javascriptreact: { line: '//', block: ['/*', '*/'] },
  typescript: { line: '//', block: ['/*', '*/'] },
  typescriptreact: { line: '//', block: ['/*', '*/'] },
  java: { line: '//', block: ['/*', '*/'] },
  go: { line: '//', block: ['/*', '*/'] },
  kotlin: { line: '//', block: ['/*', '*/'] },
  csharp: { line: '//', block: ['/*', '*/'] },
  swift: { line: '//', block: ['/*', '*/'] },
  c: { line: '//', block: ['/*', '*/'] },
  cpp: { line: '//', block: ['/*', '*/'] },
  rust: { line: '//', block: ['/*', '*/'] },
  php: { line: '//', block: ['/*', '*/'] },
  arduino: { line: '//', block: ['/*', '*/'] },
  // JSON with Comments — VS Code's own language for tsconfig-style files.
  jsonc: { line: '//', block: ['/*', '*/'] },

  // Block comments only, or a non-`//` line comment. A `//` here is a syntax
  // error (CSS, HTML) or a different operator entirely.
  css: { block: ['/*', '*/'] },
  scss: { line: '//', block: ['/*', '*/'] },
  less: { line: '//', block: ['/*', '*/'] },
  html: { block: ['<!--', '-->'] },
  xml: { block: ['<!--', '-->'] },
  vue: { block: ['<!--', '-->'] },
  sql: { line: '--', block: ['/*', '*/'] },

  // No comment syntax at all. Strict JSON rejects `//` and `/* */` alike, so
  // nothing can be written here without breaking the file, and the Quick Fix is
  // withheld rather than offered as a trap. Suppress these by rule or by path
  // in `.vibeguardrc.json` instead.
  json: {},
  plaintext: {},
};

/** Fallback for a language nobody has classified yet. */
const UNKNOWN_LANGUAGE_STYLE: CommentStyle = { line: '//' };

/**
 * The pragma comment to insert for `languageId`, or `null` when the language
 * has no comment syntax that survives a re-parse.
 *
 * Unknown languages fall back to `//` — the same guess as before, kept because
 * withholding the fix for every unlisted language would remove it from the long
 * tail of C-family types VS Code names differently than we do. The DIFFERENCE
 * is that shapes known to break are now listed explicitly, so the fallback only
 * applies where nobody has checked, never where someone checked and found it
 * unsafe.
 */
export function suppressionComment(languageId: string, ruleId: string): string | null {
  const directive = `vibeguard:disable-next-line ${ruleId}`;
  const style = COMMENT_STYLES[languageId] ?? UNKNOWN_LANGUAGE_STYLE;
  if (style.line !== undefined) return `${style.line} ${directive}`;
  if (style.block !== undefined) return `${style.block[0]} ${directive} ${style.block[1]}`;
  return null;
}
