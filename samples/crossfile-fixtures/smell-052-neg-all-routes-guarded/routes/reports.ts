import type { Request, Response } from 'express';
import { db } from '../db';

const summaryCache = new Map<string, unknown[]>();

export async function createReport(req: Request, res: Response): Promise<void> {
  const title = req.body.title;
  await db.query(`INSERT INTO reports (title) VALUES ('${title}')`);
  res.status(201).end();
}

export async function listReports(_req: Request, res: Response): Promise<void> {
  // `summaryCache.get(cacheKey)` is an ordinary map read and the indexer records
  // it as a route registration: `JS_ROUTE` is every `.get(` in the language. Its
  // first argument is an identifier rather than a path literal, and its
  // "handler" is that same identifier, so it has the exact shape of an endpoint
  // registered with no guard. It is here to be counted wrongly.
  const cacheKey = 'reports:list';
  const cached = summaryCache.get(cacheKey);
  const rows = cached ?? (await db.query('SELECT id, title FROM reports ORDER BY id DESC'));
  summaryCache.set(cacheKey, rows);
  res.json({ rows });
}
