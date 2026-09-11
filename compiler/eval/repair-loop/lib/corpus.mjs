/**
 * Which files of the r2 corpus the repair loop measures, and what each one is.
 *
 * The corpus is every `.c` file in ai-generated/generated-corpus/r2, in name
 * order. A file's id is its name without `.c`, spelled
 * `<model>_<framing>_<scenario>_<rep>`, and the scenario's entry in
 * ai-generated/scenarios.json gives its family and its target function. The
 * erasure family is every file whose scenario's `fam` is `erasure`, whether the
 * model wrote a wipe or not (the no-wipe files are measured too). A file whose
 * scenario is not in scenarios.json belongs to no family and is in no
 * selection.
 *
 * One definition, used by run-repair-loop.mjs and by tools/fbu-levels.mjs, so
 * that a tool which says it measures "the files the repair loop uses" measures
 * them by construction rather than through a second copy of the rule. Pure: the
 * caller lists the directory and parses scenarios.json.
 */

/** The corpus files among `names` (a directory listing), sorted. */
export function corpusFiles(names) {
  return names.filter((f) => f.endsWith('.c')).sort();
}

/**
 * What a corpus file is: {id, model, framing, scen, rep, fam, fn}, or null when
 * its scenario is not in `scenarios`.
 */
export function metaOf(file, scenarios) {
  const id = file.replace(/\.c$/, '');
  const [model, framing, sc, rep] = id.split('_');
  const m = scenarios[sc];
  return m ? { id, model, framing, scen: sc, rep, fam: m.fam, fn: m.fn } : null;
}

/** The erasure-family files among `files`, in the order given, each as {f, meta}. */
export function erasureFamily(files, scenarios) {
  return files.map((f) => ({ f, meta: metaOf(f, scenarios) })).filter((x) => x.meta && x.meta.fam === 'erasure');
}
