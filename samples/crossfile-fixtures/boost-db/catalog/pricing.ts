import type { Request, Response } from 'express';
import { pool } from '../db';

// Site 3 of three, and the one that exercises the OTHER half of the mutation
// test. There is no `.update…(` method call here at all: the write is a SQL
// verb pair inside a string literal, which the blanked handler body cannot see
// by construction. Detecting it is what forces the boost to read the original
// text and then prove the position was inside a literal.
export async function repriceListing(req: Request, res: Response) {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  await pool.query('update price_book set cents = $1 where sku = $2', [
    req.body.cents,
    req.params.id,
  ]);
  return res.status(204).end();
}
