/**
 * The cut step of tools/which-wipe-survived.mjs, as a function that can be read
 * and tested without a compiler.
 *
 * WHY THIS IS ITS OWN FILE. The tool asks its question by deletion: build the
 * family as written, then once with the SUBJECT's wipe cut out of the source,
 * then once with the CONTROL's. Everything the tool concludes rests on those two
 * cuts having removed the line each one claims to have removed. Until this file
 * existed the cut was four lines inside the tool -- a `filter` over a regex --
 * and nothing anywhere tested it. A cut that removed the wrong line, or removed
 * two lines because the pattern matched twice, produced three builds, three byte
 * counts and a plausible wrong table, with every unit test in the lane green.
 *
 * So the cut is a function here, it reports what it removed rather than only
 * what is left, and it REFUSES two ways instead of guessing:
 *
 *   no line matched     the fixture's shape changed under the tool. The tool is
 *                       asking to delete something that is not there, and the
 *                       build it would produce is the as-written build under
 *                       another name -- which reads as "deleting it changed
 *                       nothing", the tool's headline answer, for the wrong
 *                       reason. This is the failure that most wants to be loud.
 *
 *   more than one       ambiguity is not resolved by taking the first. Two lines
 *                       matching means the pattern no longer names one wipe, and
 *                       a reading attributed to "the subject's wipe" would be
 *                       about whichever one the array happened to hold first.
 *
 * The patterns live here too, so the test can check them against the generator's
 * OWN template (tools/make-lto-fixtures.sh) rather than against a string typed
 * into a test file to match them.
 */

/** The two lines the fixture generator writes, and which wipe each one is. */
export const WIPE_LINES = Object.freeze({
  subject: /^\s*secure_wipe\(key, sizeof key\);\s*$/,
  control: /^\s*memset\(keep, 0, sizeof keep\);\s*$/,
});

export const CUT_REFUSAL = Object.freeze({
  NO_MATCH: 'no-line-matched',
  AMBIGUOUS: 'more-than-one-line-matched',
});

/** A refusal, not a crash: `reason` is one of CUT_REFUSAL and is meant to be printed. */
export class VariantCutError extends Error {
  constructor(reason, message, detail = {}) {
    super(message);
    this.name = 'VariantCutError';
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * Remove the one line of `source` that `pattern` matches.
 *
 * @returns {{text: string, removedLine: string, lineNumber: number, lineCount: number}}
 *          `lineNumber` is 1-based and is returned for the caller to report, not
 *          for the caller to trust: the identity of the cut is the line's TEXT.
 * @throws  {VariantCutError} when the pattern matches zero lines or more than one.
 */
export function cutOneLine(source, pattern, which = 'the') {
  if (typeof source !== 'string') throw new TypeError('cutOneLine wants the source text');
  const lines = source.split('\n');
  const hits = [];
  for (let i = 0; i < lines.length; i++) if (pattern.test(lines[i])) hits.push(i);
  if (hits.length === 0) {
    throw new VariantCutError(
      CUT_REFUSAL.NO_MATCH,
      `no line matches the ${which} wipe (${pattern}); the fixture's shape changed under the tool, and `
      + 'a build with nothing deleted would read as "deleting it changed nothing"',
      { which, pattern: String(pattern), matched: 0 },
    );
  }
  if (hits.length > 1) {
    throw new VariantCutError(
      CUT_REFUSAL.AMBIGUOUS,
      `${hits.length} lines match the ${which} wipe (${pattern}), at lines ${hits.map((i) => i + 1).join(', ')}; `
      + 'refusing rather than taking the first, because a reading attributed to one wipe would be about '
      + 'whichever line the array happened to hold first',
      { which, pattern: String(pattern), matched: hits.length, lineNumbers: hits.map((i) => i + 1) },
    );
  }
  const [at] = hits;
  const removedLine = lines[at];
  const kept = lines.slice(0, at).concat(lines.slice(at + 1));
  return { text: kept.join('\n'), removedLine, lineNumber: at + 1, lineCount: kept.length };
}

/**
 * The three sources the tool builds, from one `use.c`.
 *
 * @returns {{asWritten: string, subjectCut: object, controlCut: object}} where
 *          each cut is a cutOneLine result, so the caller can report WHICH line
 *          went rather than asserting that one did.
 */
export function cutWipeVariants(source) {
  return {
    asWritten: source,
    subjectCut: cutOneLine(source, WIPE_LINES.subject, "subject's"),
    controlCut: cutOneLine(source, WIPE_LINES.control, "control's"),
  };
}

/* ------------------------------------------------------ the real template --
 *
 * The fixture is generated, not committed (a path segment `fixtures` under
 * compiler/ is refused outright by scripts/check-packaging-invariants.mjs), so
 * the only tracked copy of the text the cut runs against is the heredoc inside
 * tools/make-lto-fixtures.sh. Reading it from there is what makes the cut's test
 * a test of THIS lane's fixture rather than of a string that resembles it: an
 * edit to the generator that renames a buffer turns the test red in the same
 * commit, instead of turning the next measurement into a wrong table.
 */

const TEMPLATE_FN = 'xtu_use_c() {';
const HEREDOC_OPEN = "cat <<'FIXTURE_EOF'";
const HEREDOC_CLOSE = 'FIXTURE_EOF';

/** The `@NOINLINE@` marker the generator substitutes or deletes. */
export const NOINLINE_MARKER = '@NOINLINE@';

/**
 * The use.c template, lifted out of the generator script's own heredoc.
 * Refuses (throws) rather than returning something plausible when the script's
 * shape has changed -- an empty or truncated template would make every cut test
 * below it vacuous.
 */
export function useTemplateFrom(generatorScript) {
  // THE ANCHORS ARE EXACT, BECAUSE THE GENERATOR'S ARE. Every line matched
  // below is matched the way the shell matches it, not the way a reader skims
  // it: `sed 's/^@NOINLINE@$/.../'` anchors both ends, and a heredoc opened
  // with <<'FIXTURE_EOF' (no dash) is closed only by FIXTURE_EOF in column 0.
  // These were `l.trim() === ...`, which is a LOOSER pattern than the thing it
  // stands in for: an indented FIXTURE_EOF inside the template would have
  // closed the heredoc here and not in bash, truncating the template every cut
  // test below is run against, and an indented @NOINLINE@ would have been
  // rendered here and left in place by sed. A lifted copy that matches more
  // than the original is not a copy of it.
  if (generatorScript.includes('\r')) {
    throw new VariantCutError(
      CUT_REFUSAL.NO_MATCH,
      'the generator script has CR line endings: bash does not close a heredoc whose terminator carries one, and '
      + 'sed\'s ^...$ does not match a line that ends in one, so nothing lifted out of it here would be the text '
      + 'the fixture is actually written from',
    );
  }
  const lines = generatorScript.split('\n');
  const fnAt = lines.findIndex((l) => l === TEMPLATE_FN);
  if (fnAt < 0) throw new VariantCutError(CUT_REFUSAL.NO_MATCH, `the generator has no \`${TEMPLATE_FN}\` function`);
  const openAt = lines.findIndex((l, i) => i > fnAt && l === HEREDOC_OPEN);
  if (openAt < 0) throw new VariantCutError(CUT_REFUSAL.NO_MATCH, `\`${TEMPLATE_FN}\` does not open a ${HEREDOC_CLOSE} heredoc`);
  const closeAt = lines.findIndex((l, i) => i > openAt && l === HEREDOC_CLOSE);
  if (closeAt < 0) throw new VariantCutError(CUT_REFUSAL.NO_MATCH, `the ${HEREDOC_CLOSE} heredoc is not closed`);
  const text = `${lines.slice(openAt + 1, closeAt).join('\n')}\n`;
  const markers = text.split('\n').filter((l) => l === NOINLINE_MARKER).length;
  if (markers !== 2) {
    throw new VariantCutError(
      CUT_REFUSAL.AMBIGUOUS,
      `the template carries ${markers} \`${NOINLINE_MARKER}\` lines, not 2: the two families are no longer `
      + 'one template with one intervention, and rendering either of them here would be a guess',
      { markers },
    );
  }
  return text;
}

/**
 * The generator's two seds, in the two families' spelling. `xtu` replaces the
 * marker with the attribute; `xtu-inline` deletes the marker line outright.
 */
export function renderUseC(template, family) {
  const lines = template.split('\n');
  // `s/^@NOINLINE@$/.../` and `/^@NOINLINE@$/d` -- both anchored at both ends,
  // so both are an exact line comparison here and not a trimmed one.
  if (family === 'xtu') return lines.map((l) => (l === NOINLINE_MARKER ? '__attribute__((noinline))' : l)).join('\n');
  if (family === 'xtu-inline') return lines.filter((l) => l !== NOINLINE_MARKER).join('\n');
  throw new VariantCutError(CUT_REFUSAL.NO_MATCH, `no family named ${family} is rendered from this template`);
}
