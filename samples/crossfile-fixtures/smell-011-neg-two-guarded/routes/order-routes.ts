import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { cancelOrder, createOrder, updateOrder } from '../controllers/order-controller';

export const orderRouter = Router();

orderRouter.post('/orders', requireAdmin, createOrder);
orderRouter.put('/orders/:id', requireAdmin, updateOrder);

orderRouter.post('/orders/:id/cancel', cancelOrder);
