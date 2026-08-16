import { withAnyRole } from '../../lib/authz';
import { listMembers } from '../../lib/store';

const handler = withAnyRole(['admin', 'owner'], async (req, res) => {
  res.status(200).json(await listMembers(req.query.teamId));
});

export default handler;
