import express from 'express';
import { app } from '../app';

// A probe app, mounted without the guard so the router can be exercised
// directly. Registering it under authentication would test the guard instead of
// the route.
const probe = express();

probe.get('/invoices', (_req, res) => {
  res.json({ rows: [] });
});

export { app, probe };
