// VG-SMELL-041 POSITIVE — the INVERTED ordering, with a transforming sanitizer.
//
// The escaping this handler needs is written, is correct, and runs one
// statement too late: the row set has already been fetched with the raw term
// interpolated into the statement. Nothing in the structure of the code says
// `escapeLike` has to come first — that is the temporal coupling.
//
// Written as an INLINE arrow handler at the route registration on purpose. The
// rule locates the enclosing function by body containment rather than by name,
// and an inline handler is the shape where a name-based lookup would fail.
import express from 'express';
import { db } from './db';
import { escapeLike } from './sanitize/escape';

export const router = express.Router();

router.get('/search', async (req, res) => {
  const term = req.query.term;
  const rows = await db.query(`SELECT id, title FROM items WHERE title LIKE '%${term}%'`);
  // Too late: the statement above already ran.
  const safeTerm = escapeLike(term);
  res.json({ term: safeTerm, rows });
});
