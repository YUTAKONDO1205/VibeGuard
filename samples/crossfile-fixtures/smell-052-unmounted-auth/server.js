const express = require('express');
const { renderProfile } = require('./handlers/profile');

const app = express();

app.get('/profile', renderProfile);

module.exports = { app };
