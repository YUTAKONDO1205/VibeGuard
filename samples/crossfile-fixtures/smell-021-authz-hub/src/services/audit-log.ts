import type { Db } from '../db/client.js';

export async function recordDecision(db: Db, userId: string, action: string, allowed: boolean): Promise<void> {
  await db.query('insert into audit (user_id, action, allowed) values ($1, $2, $3)', [userId, action, allowed]);
}
