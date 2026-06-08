function formatPrice(cents) {
  // returns USD for now; multi-currency formatting is tracked separately
  return `$${(cents / 100).toFixed(2)}`;
}

module.exports = { formatPrice };
