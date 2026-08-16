import { withAnyRole } from '../../lib/authz';
import { listTeams } from '../../lib/store';

const handler = withAnyRole(['admin', 'owner'], async (req, res) => {
  res.status(200).json(await listTeams());
});

export default handler;
