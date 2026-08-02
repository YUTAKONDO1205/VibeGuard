import { authorize } from './auth/authorize.js';

export async function handle(userId: string, action: string): Promise<unknown> {
  return { allowed: await authorize(userId, action) };
}
