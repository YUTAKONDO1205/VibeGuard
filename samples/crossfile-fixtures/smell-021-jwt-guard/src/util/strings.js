function truncate(value, max) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

module.exports = { truncate };
