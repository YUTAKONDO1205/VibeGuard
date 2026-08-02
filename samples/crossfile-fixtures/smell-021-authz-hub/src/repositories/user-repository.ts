import type { Db } from '../db/client.js';
import type { User } from '../models/user.js';

export async function findUserById(db: Db, id: string): Promise<User | undefined> {
  const rows = await db.query<User>('select * from users where id = $1', [id]);
  return rows[0];
}
