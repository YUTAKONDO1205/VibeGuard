// NEGATIVE fixture: two ORM table definitions that reference each other because
// the ROWS reference each other. Every schema-first ORM documents this shape, and
// the modules hold table metadata rather than runtime security state — the word
// that would put this file in the population is a column name.
import { serverTable } from './server.js';

export const certificateTable = {
  name: 'certificate',
  columns: ['certificateId', 'privateKey', 'serverId'],
  belongsTo: () => serverTable,
};

export function certificateColumns(): string[] {
  return certificateTable.columns;
}
