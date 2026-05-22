/**
 * Tiny glob → RegExp translator.
 *
 * Supports the subset of patterns we actually use in config files:
 *   `*`   — any chars except `/`
 *   `**`  — any chars including `/` (optionally followed by `/`)
 *   `?`   — any single char except `/`
 *
 * Patterns are matched against forward-slash paths (the scanner normalises
 * Windows backslashes before this is called). Matching is anchored — the
 * pattern must match the entire path.
 */

const REGEX_META = new Set('.+^$()|[]{}\\');

function globToRegex(glob: string): RegExp {
  let re = '^';
  let i = 0;
  while (i < glob.length) {
    const c = glob[i] ?? '';
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**` — any chars including slashes. If followed by `/`, consume the
        // slash so that `dir/**/file` matches `dir/file` too.
        i += 2;
        if (glob[i] === '/') {
          re += '(?:.*/)?';
          i += 1;
        } else {
          re += '.*';
        }
      } else {
        re += '[^/]*';
        i += 1;
      }
    } else if (c === '?') {
      re += '[^/]';
      i += 1;
    } else if (REGEX_META.has(c)) {
      re += '\\' + c;
      i += 1;
    } else {
      re += c;
      i += 1;
    }
  }
  re += '$';
  return new RegExp(re);
}

export function matchesGlob(pattern: string, path: string): boolean {
  const normalized = path.replace(/\\/g, '/');
  return globToRegex(pattern).test(normalized);
}

export function matchesAnyGlob(patterns: string[] | undefined, path: string): boolean {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((p) => matchesGlob(p, path));
}
