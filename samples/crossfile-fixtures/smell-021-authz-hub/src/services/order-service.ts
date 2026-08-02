import { db } from '../db/client.js';
import type { Order } from '../models/order.js';

export async function placeOrder(tenantId: string, payload: unknown): Promise<Order[]> {
  return db.query<Order>('insert into orders (tenant_id, payload) values ($1, $2) returning *', [tenantId, payload]);
}
