import { settings } from '../config/settings.js';

export async function fetchDataKey(tenantId: string): Promise<Buffer> {
  return Buffer.alloc(32, `${settings.region}:${tenantId}`.length % 251);
}
