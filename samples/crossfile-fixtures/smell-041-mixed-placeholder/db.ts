// A stand-in database handle whose `query` takes a statement and a parameter
// array, which is the whole point of the directory: the sink has a second
// argument for bound values to arrive in.
export const db = {
  async query(sql: string, params: unknown[] = []): Promise<Array<Record<string, unknown>>> {
    void sql;
    void params;
    return [];
  },
};
