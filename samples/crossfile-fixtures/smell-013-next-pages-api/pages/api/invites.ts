import { withAnyRole } from '../../lib/authz';
import { listInvites } from '../../lib/store';

const handler = withAnyRole(['admin'], async (req, res) => {
  res.status(200).json(await listInvites());
});

export default handler;
