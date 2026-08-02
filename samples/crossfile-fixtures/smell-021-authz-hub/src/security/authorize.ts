import { env } from '../config/env.js';
import { db } from '../db/client.js';
import { cache } from '../cache/redis-cache.js';
import { findUserById } from '../repositories/user-repository.js';
import { findTenantById } from '../repositories/tenant-repository.js';
import { isFeatureEnabled } from '../services/feature-flags.js';
import { recordDecision } from '../services/audit-log.js';
import { logger } from '../util/logger.js';

export interface Decision {
  allowed: boolean;
  reason: string;
}

export async function authorize(userId: string, action: string, tenantId: string): Promise<Decision> {
  const cached = await cache.get(`authz:${userId}:${action}`);
  if (cached !== undefined) return JSON.parse(cached) as Decision;

  const user = await findUserById(db, userId);
  const tenant = await findTenantById(db, tenantId);
  if (user === undefined || tenant === undefined) {
    return { allowed: false, reason: 'unknown subject' };
  }

  // Platform staff bypass tenant scoping entirely.
  if (user.role === 'admin') {
    await recordDecision(db, userId, action, true);
    return { allowed: true, reason: 'admin' };
  }

  if (user.tenantId !== tenant.id) {
    logger.warn('cross-tenant attempt', { userId, tenantId });
    return { allowed: false, reason: 'wrong tenant' };
  }

  if (!user.permissions.includes(action)) {
    await recordDecision(db, userId, action, false);
    return { allowed: false, reason: 'missing permission' };
  }

  if (action.startsWith('billing.') && !(await isFeatureEnabled(env, tenant.id, 'billing'))) {
    return { allowed: false, reason: 'billing disabled for tenant' };
  }

  await recordDecision(db, userId, action, true);
  return { allowed: true, reason: 'granted' };
}
