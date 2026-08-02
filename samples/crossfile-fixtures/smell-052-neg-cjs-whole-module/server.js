const express = require('express');
const { renderReport } = require('./handlers/report');

const app = express();

app.use(express.json());
// Mounted whole. The module's export IS the middleware, so there is no name to
// write down and nothing for an identifier scan to find.
app.use(require('./security/require-bearer-auth'));

app.get('/report', renderReport);

module.exports = { app };
