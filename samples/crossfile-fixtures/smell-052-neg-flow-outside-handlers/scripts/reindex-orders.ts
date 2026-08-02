import { db } from '../db';

// A maintenance script. `process.argv` is an operator's shell argument, and the
// function is never registered against a route, so no middleware could have
// stood in front of it.
export async function reindexOrders(): Promise<void> {
  const term = process.argv[2];
  const rows = await db.query(`SELECT id FROM orders WHERE note LIKE '%${term}%'`);
  process.stdout.write(`${rows.length} rows\n`);
}
