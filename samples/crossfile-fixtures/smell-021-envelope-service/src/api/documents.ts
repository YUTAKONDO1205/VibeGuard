import { sealPayload, openPayload } from '../services/envelope.js';

export async function storeDocument(tenantId: string, body: Buffer): Promise<string> {
  return sealPayload(tenantId, body);
}

export async function readDocument(tenantId: string, packed: string): Promise<Buffer> {
  return openPayload(tenantId, packed);
}
