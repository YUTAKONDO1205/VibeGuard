// Written when the profile endpoint was written, exported the CommonJS way, and
// never passed to `app.get` or `app.use`. `server.js` does not require this
// file, so `/profile` answers every anonymous request.
function requireAuth(req, res, next) {
  const header = req.get('authorization');
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  next();
}

module.exports = { requireAuth };
