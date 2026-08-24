// Protections that hold in the build the author runs and are absent from the
// build everyone else runs.
//
// Measured 2026-08-23 with esbuild 0.21.5 and no flags beyond `--minify`:
// `deleteUser` below compiles to `function o(s,e){return db.remove(e)}`. The
// parameter carrying the caller's identity is never read.

import { db } from './db.js';

export function deleteUser(session, targetId) {
  // VG-AUTH-009 — the decision only exists while NODE_ENV is not "production".
  if (process.env.NODE_ENV !== 'production') {
    if (!session.isAdmin) throw new Error('forbidden');
  }
  return db.remove(targetId);
}

export function promoteUser(session, targetId) {
  // VG-AUTH-010 — console.assert does not throw, and bundlers drop it.
  console.assert(session.hasPermission, 'caller must hold the permission');
  return db.setRole(targetId, 'admin');
}

export function purgeTenant(session, tenantId) {
  // VG-AUTH-009 again, spelled with the framework's own dev flag.
  if (import.meta.env.DEV) {
    if (!session.isOwner) throw new Error('unauthorized');
  }
  return db.dropTenant(tenantId);
}
