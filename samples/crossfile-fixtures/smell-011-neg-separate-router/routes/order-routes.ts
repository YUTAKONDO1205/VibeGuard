import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { createOrder, removeOrder, updateOrder } from '../controllers/order-controller';

export const orderRouter = Router();

orderRouter.post('/orders', requireAdmin, createOrder);
orderRouter.put('/orders/:id', requireAdmin, updateOrder);
orderRouter.delete('/orders/:id', requireAdmin, removeOrder);
