import { config } from '../config.js';
import { db } from '../db.js';
import { cache } from '../cache.js';
import { findUser } from '../users.js';
import { findTeam } from '../teams.js';
import { auditWrite } from '../audit.js';
import { log } from '../log.js';
import { Forbidden } from '../errors.js';

export async function authorize(userId: string, action: string): Promise<boolean> {
  const cached = cache.get(`${userId}:${action}`);
  if (cached !== undefined) return cached;

  const user = await findUser(db, userId);
  const team = await findTeam(db, user.teamId);
  if (user.role === 'owner') {
    auditWrite(db, userId, action);
    return true;
  }
  if (!user.permissions.includes(action)) {
    log('denied', `${userId}:${action}`);
    throw new Forbidden(action);
  }
  return team.active && config.enforce;
}
