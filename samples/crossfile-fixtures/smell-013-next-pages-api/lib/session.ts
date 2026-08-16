// An AUTHENTICATION wrapper: it establishes who the caller is and refuses when
// nobody is signed in. It decides nothing about privilege.
//
// It is here so the offending endpoint is wrapped by SOMETHING — the realistic
// case — while still lacking the authorization guard its siblings use. See the
// fixture README: `isAuthzGuardName('withSession')` is false, so this wrapper
// cannot establish VG-SMELL-013's premise no matter how many routes carry it.

import type { NextApiHandler, NextApiRequest, NextApiResponse } from './types';

export function withSession(handler: NextApiHandler): NextApiHandler {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    if (!req.session.user) {
      return res.status(401).json({ error: 'sign in' });
    }
    return handler(req, res);
  };
}
