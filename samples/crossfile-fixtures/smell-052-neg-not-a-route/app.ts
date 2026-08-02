import express from 'express';
import { requireAdminRole } from './security/require-admin-role';
import { searchIncidents } from './routes/incidents';
import { config, DEFAULT_DATABASE_URL } from './config';
import { store, reportCacheKey } from './store';
import { handlers } from './handlers';

const app = express();

app.use(express.json());

// A settings lookup: `.get(` with a string first argument that is not a path.
const databaseUrl = config.get('database.url', DEFAULT_DATABASE_URL);
// A cache lookup: `.get(` whose only argument is not a literal at all, so there
// is no path and the argument lands in the handler slot.
const cachedReport = store.get(reportCacheKey);
// A registration whose handler is a computed member access, so there is no
// handler identifier to record and no handler symbol to attribute a flow to.
app.get('/incidents', handlers['listIncidents']);

app.get('/search', requireAdminRole, searchIncidents);

export { app, databaseUrl, cachedReport };
