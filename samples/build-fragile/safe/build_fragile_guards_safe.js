// The same three functions, written so the decision survives the build.
//
// The pairing with samples/vulnerable/build_fragile_guards.js is the point: the
// difference between the two files is not "more checks", it is where the checks
// sit relative to a conditional the bundler can fold.

import { db } from './db.js';

export function deleteUser(session, targetId) {
  // Unconditional. Nothing here is a compile-time constant, so nothing here is
  // eliminated.
  if (!session.isAdmin) throw new Error('forbidden');
  return db.remove(targetId);
}

export function promoteUser(session, targetId) {
  // Control flow that refuses, rather than a console call that logs and returns.
  if (!session.hasPermission) throw new Error('forbidden');
  return db.setRole(targetId, 'admin');
}

export function purgeTenant(session, tenantId) {
  if (!session.isOwner) throw new Error('unauthorized');
  // A development-only block is fine when what it does is describe, not decide.
  if (import.meta.env.DEV) {
    logger.debug('purging tenant', tenantId);
  }
  return db.dropTenant(tenantId);
}
