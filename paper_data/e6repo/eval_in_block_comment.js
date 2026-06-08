// E6 fixture — eval().
// TREATMENT: an eval() call shown inside a /* */ block comment (a tutorial
// snippet, not executed). CONTROL: a real eval() in the function body.
// Item ① should down-rank the block-comment occurrence (high -> low) while the
// live call keeps critical/high.

/*
 * Example you might copy from a blog post (do NOT ship this):
 *   const result = eval(userExpression);
 *   return result;
 */
function run(userExpression) {
  // CONTROL: a real eval on a request-derived value. Must stay high.
  return eval(userExpression);
}

module.exports = { run };
