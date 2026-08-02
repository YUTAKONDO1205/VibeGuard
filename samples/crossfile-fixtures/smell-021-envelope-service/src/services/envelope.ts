import crypto from 'node:crypto';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { settings } from '../config/settings.js';
import { store } from '../storage/blob-store.js';
import { fetchDataKey } from '../storage/key-store.js';
import { metrics } from '../telemetry/metrics.js';
import { trace } from '../telemetry/trace.js';
import { encodeBase64, decodeBase64 } from '../util/base64.js';
import { chunk } from '../util/chunk.js';
import { RetryPolicy } from '../util/retry.js';

const ALGORITHM = 'aes-256-gcm';

export async function sealPayload(tenantId: string, plaintext: Buffer): Promise<string> {
  const span = trace.start('envelope.seal');
  const dataKey = await new RetryPolicy(3).run(() => fetchDataKey(tenantId));
  const iv = randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, dataKey, iv);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const packed = encodeBase64(Buffer.concat([iv, cipher.getAuthTag(), body]));
  await store.put(`${settings.bucket}/${tenantId}`, packed);
  metrics.increment('envelope.sealed');
  span.end();
  return packed;
}

export async function openPayload(tenantId: string, packed: string): Promise<Buffer> {
  const raw = decodeBase64(packed);
  const dataKey = await fetchDataKey(tenantId);
  const decipher = createDecipheriv(ALGORITHM, dataKey, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  const parts = chunk(raw.subarray(28), 4096).map((part) => decipher.update(part));
  metrics.increment('envelope.opened');
  return Buffer.concat([...parts, decipher.final()]);
}
