import express from 'express';
import { app } from '../app';

// A probe endpoint that echoes its own query string, so the suite can assert
// that the echo happened. The untrusted-looking flow here is the test's subject,
// not the service's behaviour.
const probe = express();

probe.get('/echo', (req, res) => {
  const message = req.query.message;
  res.send(`<p>${message}</p>`);
});

export { app, probe };
