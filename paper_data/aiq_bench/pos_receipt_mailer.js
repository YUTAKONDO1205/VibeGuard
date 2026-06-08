const nodemailer = require("nodemailer");

async function sendReceipt(order) {
  const transport = nodemailer.createTransport(process.env.SMTP_URL);
  await transport.sendMail({
    from: "billing@example.com",
    to: order.customerEmail,
    subject: "Your receipt",
    text: renderReceipt(order),
  });
}

module.exports = { sendReceipt };
