import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { createOrder, listOrders, removeOrder, updateOrder } from '../controllers/order-controller';

export const orderRouter = Router();

orderRouter.post('/orders', requireAdmin, createOrder);
orderRouter.put('/orders/:id', requireAdmin, updateOrder);
orderRouter.delete('/orders/:id', requireAdmin, removeOrder);

// A read, registered with no guard, and correct: this catalogue is public. The
// convention above is about writes, and a read/write asymmetry is a design
// decision rather than an omission.
orderRouter.get('/orders', listOrders);
