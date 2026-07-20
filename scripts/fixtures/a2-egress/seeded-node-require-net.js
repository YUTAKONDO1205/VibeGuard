// SEEDED VIOLATION — negative control for sec-a2-egress-scan.mjs. Never executed.
// Expected sink: node-net-import (net) via CommonJS require, the form a bundler
// leaves behind when it inlines a dependency rather than an authored import.
const net = require('net');

module.exports = function report(payload) {
  const socket = net.connect(4444, 'telemetry.example.invalid');
  socket.end(payload);
};
