// VibeGuard sample: Express server with insecure session + wildcard CORS.

const express = require('express');
const session = require('express-session');
const cors = require('cors');

const app = express();

// VG-FW-003 — wildcard CORS origin.
app.use(cors({ origin: '*' }));

// VG-AUTH-006 — session cookie missing both secure and httpOnly.
app.use(
  session({
    secret: 'change-me',
    cookie: { secure: false, httpOnly: false },
  }),
);

app.get('/', (req, res) => res.send('ok'));

app.listen(3000);
