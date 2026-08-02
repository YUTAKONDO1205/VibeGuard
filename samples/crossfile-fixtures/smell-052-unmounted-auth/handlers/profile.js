function renderProfile(req, res) {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
}

module.exports = { renderProfile };
