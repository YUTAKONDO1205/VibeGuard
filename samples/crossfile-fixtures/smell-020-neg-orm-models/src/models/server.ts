import { certificateTable } from './certificate.js';

export const serverTable = {
  name: 'server',
  columns: ['serverId', 'hostname'],
  hasMany: () => certificateTable,
};

export function serverColumns(): string[] {
  return serverTable.columns;
}
