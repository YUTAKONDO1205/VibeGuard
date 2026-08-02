function log(message, detail) {
  process.stdout.write(`${message} ${detail}\n`);
}

module.exports = { log };
