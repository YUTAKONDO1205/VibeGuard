// A helper namespace, the shape a project collects this kind of function into.
//
// The doubling is written with `split`/`join` rather than a regex literal
// containing a quote: a `/'/g` in a fixture is a needless bet on the lexical
// blanker's regex handling, and a fixture whose indexing is in doubt cannot pin
// anything.
export const sanitizers = {
  escapeSql(value: string): string {
    return String(value).split("'").join("''");
  },
};
