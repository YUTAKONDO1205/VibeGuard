const counters = new Map();

function bumpCounter(name) {
  counters.set(name, (counters.get(name) || 0) + 1);
}

module.exports = { bumpCounter };
