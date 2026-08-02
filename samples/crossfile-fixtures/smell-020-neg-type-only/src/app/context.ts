import { verifyPassword } from '../auth/verifier.js';

export interface CallerContext {
  subject: string;
  secret: string;
}

export function isCallerKnown(ctx: CallerContext): boolean {
  return verifyPassword(ctx, ctx.secret);
}
