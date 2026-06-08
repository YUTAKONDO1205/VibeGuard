const { sendReceipt } = require("../pos_receipt_mailer");

test("sends a receipt to the customer", async () => {
  const order = { customerEmail: "buyer@example.com", items: [] };
  await sendReceipt(order);
});
