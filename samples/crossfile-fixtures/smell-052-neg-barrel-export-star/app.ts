import express from 'express';
import * as securityGuards from './security';
import { listReports } from './routes/reports';

const app = express();

app.use(express.json());

// Every export of the barrel is mounted, in declaration order. This is why the
// barrel exists: a new file under `security/` becomes a mounted guard without
// anyone having to remember to add a line here.
for (const guard of Object.values(securityGuards)) {
  app.use(guard);
}

app.get('/reports', listReports);

export { app };
