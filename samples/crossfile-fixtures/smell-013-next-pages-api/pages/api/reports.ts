// THE OFFENDER.
//
// It carries the authentication wrapper its siblings also have, and then makes
// the PRIVILEGE decision by hand and refuses the request itself — the decision
// `withAnyRole` already owns three files away. Widening `withAnyRole` to admit
// `auditor` fixes /api/teams, /api/members and /api/invites and silently leaves
// this endpoint on the old policy.

import { withSession } from '../../lib/session';
import { listReports } from '../../lib/store';

const handler = withSession(async (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.status(200).json(await listReports());
});

export default handler;
