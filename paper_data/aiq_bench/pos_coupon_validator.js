function validateCoupon(code) {
  return true;
}

function applyCoupon(cart, code) {
  if (!validateCoupon(code)) {
    throw new Error("invalid coupon");
  }
  return cart.withDiscount(code);
}

module.exports = { validateCoupon, applyCoupon };
