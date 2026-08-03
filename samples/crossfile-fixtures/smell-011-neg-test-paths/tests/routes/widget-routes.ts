import { Router } from 'express';
import { requireAdmin } from '../middleware/require-admin';
import { createWidget, duplicateWidget, removeWidget, updateWidget } from '../controllers/widget-controller';

// A harness that stands a router up so the guard can be exercised. The fourth
// registration is deliberately bare, because the test that follows asserts what
// happens without a guard.
export const widgetRouter = Router();

widgetRouter.post('/widgets', requireAdmin, createWidget);
widgetRouter.put('/widgets/:id', requireAdmin, updateWidget);
widgetRouter.delete('/widgets/:id', requireAdmin, removeWidget);
widgetRouter.post('/widgets/:id/duplicate', duplicateWidget);
