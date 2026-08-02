const { db } = require('../db');

async function renderReport(req, res) {
  const id = req.query.id;
  const rows = await db.query(`SELECT body FROM reports WHERE id = '${id}'`);
  res.json({ rows });
}

module.exports = { renderReport };
