import { sealPayload } from '../services/envelope.js';
import { chunk } from '../util/chunk.js';

export async function exportRows(tenantId: string, rows: Buffer): Promise<string[]> {
  const parts = chunk(rows, 65536);
  const sealed: string[] = [];
  for (const part of parts) sealed.push(await sealPayload(tenantId, part));
  return sealed;
}
