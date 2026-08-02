import { authorize } from '../security/authorize.js';
import { placeOrder } from '../services/order-service.js';

export async function createOrder(userId: string, tenantId: string, payload: unknown): Promise<unknown> {
  const decision = await authorize(userId, 'orders.create', tenantId);
  if (!decision.allowed) return { status: 403, reason: decision.reason };
  return { status: 201, body: await placeOrder(tenantId, payload) };
}
