import { Router } from 'express';
import { validateOrderBody } from '../middleware/validate-order-body';
import { cancelOrder, createOrder, removeOrder, updateOrder } from '../controllers/order-controller';

export const orderRouter = Router();

orderRouter.post('/orders', validateOrderBody, createOrder);
orderRouter.put('/orders/:id', validateOrderBody, updateOrder);
orderRouter.delete('/orders/:id', validateOrderBody, removeOrder);

orderRouter.post('/orders/:id/cancel', cancelOrder);
