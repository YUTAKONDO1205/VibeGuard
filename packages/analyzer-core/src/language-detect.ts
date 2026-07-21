const EXT_TO_LANGUAGE: Record<string, string> = {
  '.js': 'javascript',
  '.cjs': 'javascript',
  '.mjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.pyw': 'python',
  '.rb': 'ruby',
  '.go': 'go',
  '.java': 'java',
  '.kt': 'kotlin',
  '.cs': 'csharp',
  '.php': 'php',
  '.rs': 'rust',
  '.swift': 'swift',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.hpp': 'cpp',
  '.cc': 'cpp',
  // C++ dialects and header/impl extensions. `.ino` is an Arduino sketch, which
  // is a C++ dialect — no separate profile, it rides the cpp rules and the cpp
  // canonicalizer arm. `.hh` is the GNU C++ header convention, `.cxx` a common
  // C++ source extension, `.ipp` an inline-implementation header. All map to
  // cpp, which already has a LINE_COMMENT_SPEC and a LANGUAGE_PROFILE, so this
  // is a mapping change with no new language surface (VG-EMB 17c EMB-LANG).
  '.ino': 'cpp',
  '.hh': 'cpp',
  '.cxx': 'cpp',
  '.ipp': 'cpp',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.json': 'json',
  '.toml': 'toml',
  '.sql': 'sql',
  '.html': 'html',
};

export function detectLanguageFromPath(filePath: string): string | undefined {
  const lower = filePath.toLowerCase();
  for (const [ext, lang] of Object.entries(EXT_TO_LANGUAGE)) {
    if (lower.endsWith(ext)) return lang;
  }
  return undefined;
}

/** Best-effort fallback when a path is not supplied. */
export function detectLanguageFromContent(content: string): string | undefined {
  if (/^\s*#!\/usr\/bin\/env\s+python|^\s*from\s+\w+\s+import|^\s*def\s+\w+\s*\(/m.test(content)) {
    return 'python';
  }
  if (/^\s*import\s+.*from\s+["']|^\s*const\s+\w+\s*=\s*require\(/m.test(content)) {
    return 'javascript';
  }
  if (/^\s*interface\s+\w+|:\s*string\s*[;,)=]|:\s*number\s*[;,)=]/m.test(content)) {
    return 'typescript';
  }
  if (/^\s*package\s+\w+;|public\s+class\s+\w+/m.test(content)) {
    return 'java';
  }
  if (/^\s*package\s+\w+\s*$|func\s+\w+\s*\(/m.test(content)) {
    return 'go';
  }
  return undefined;
}
