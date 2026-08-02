import type { Env } from '../config/env.js';

const enabled = new Set(['billing', 'exports']);

export async function isFeatureEnabled(env: Env, tenantId: string, flag: string): Promise<boolean> {
  return enabled.has(flag) && env.region !== 'sandbox' && tenantId.length > 0;
}
