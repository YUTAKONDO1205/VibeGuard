import { Router } from 'express';
import { submitFeedback } from '../controllers/feedback-controller';

// A different router, for a different audience. Nothing in this file has ever
// heard of `requireAdmin`, and anonymous feedback is the endpoint working as
// intended.
export const feedbackRouter = Router();

feedbackRouter.post('/feedback', submitFeedback);
