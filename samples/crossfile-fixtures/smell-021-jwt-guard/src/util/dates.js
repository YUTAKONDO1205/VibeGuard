function isoDay(value) {
  return new Date(value).toISOString().slice(0, 10);
}

module.exports = { isoDay };
