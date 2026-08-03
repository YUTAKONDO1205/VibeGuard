import { Router } from 'express';
import passport from 'passport';
import { cancelOrder, createOrder, removeOrder, updateOrder } from '../controllers/order-controller';

export const orderRouter = Router();

orderRouter.post('/orders', passport.authenticate('jwt'), createOrder);
orderRouter.put('/orders/:id', passport.authenticate('jwt'), updateOrder);
orderRouter.delete('/orders/:id', passport.authenticate('jwt'), removeOrder);

orderRouter.post('/orders/:id/cancel', cancelOrder);
