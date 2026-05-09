// VibeGuard safe sample: Express session + CORS done right.
// This file MUST produce zero findings.

const express = require('express');
const session = require('express-session');
const cors = require('cors');

const app = express();

// Allowed origins are listed explicitly — no wildcard.
app.use(
  cors({
    origin: ['https://app.example.com'],
    credentials: true,
  }),
);

// Session cookie locked down: secure over TLS, not visible to JS,
// and SameSite to mitigate CSRF.
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  }),
);

app.get('/', (req, res) => res.send('ok'));

app.listen(3000);
