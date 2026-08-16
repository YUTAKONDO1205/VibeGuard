// The project's authorization convention. Three endpoints delegate to it.
//
// This is a higher-order guard rather than an Express middleware, because that
// is what a Next.js `pages/api` project has to write: there is no `router.get`
// to name a middleware in, so the guard WRAPS the handler instead.

import type { NextApiHandler, NextApiRequest, NextApiResponse } from './types';

export function withAnyRole(allowed: string[], handler: NextApiHandler): NextApiHandler {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const role = req.session.user.role;
    if (!allowed.includes(role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return handler(req, res);
  };
}
