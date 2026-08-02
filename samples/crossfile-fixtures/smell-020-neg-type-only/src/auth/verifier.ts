// NEGATIVE fixture: the two files DO name each other, so the raw dependency
// graph has a cycle. One direction is `import type`, which TypeScript erases, so
// no cycle exists when the program runs.
import type { CallerContext } from '../app/context.js';

export function verifyPassword(ctx: CallerContext, secret: string): boolean {
  return ctx.secret === secret;
}
