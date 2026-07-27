// In-memory stand-ins with the SHAPES the boost's data-mutation test keys off:
// a document-collection object with `updateOne` / `deleteOne`, and a connection
// pool whose `query` takes a parameterised statement. Nothing here is a handler,
// so nothing here is a check site — the file exists so the calls in
// `catalog/` resolve to something and read as real code.
const documents: Array<{ id: string; title: string }> = [];

export const listingCollection = {
  async updateOne(filter: { id: string }, patch: { $set: { title: string } }) {
    const found = documents.find((d) => d.id === filter.id);
    if (found) found.title = patch.$set.title;
  },
  async deleteOne(filter: { id: string }) {
    const kept = documents.filter((d) => d.id !== filter.id);
    documents.length = 0;
    documents.push(...kept);
  },
};

export const pool = {
  // Parameterised on purpose: the statement is a constant and the values arrive
  // out of band, so this fixture says "the handler mutates" without also saying
  // "the handler is injectable" and pulling the single-file SQL rules in.
  async query(_statement: string, _values: unknown[]) {
    return { rowCount: 0 };
  },
};
