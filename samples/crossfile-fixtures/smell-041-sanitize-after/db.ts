// A stand-in database handle. It exists so the fixture's sink is a `db.query(`
// call on a receiver the taint sink table recognises, rather than a bare name
// that would make the fixture depend on a driver package being installed.
export const db = {
  async query(sql: string): Promise<Array<Record<string, unknown>>> {
    void sql;
    return [];
  },
};
