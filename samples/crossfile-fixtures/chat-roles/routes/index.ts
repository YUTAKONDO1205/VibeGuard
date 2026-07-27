import { Router } from 'express';
import { renderThread, summarise } from '../controllers/threads';
import { replay } from '../controllers/replay';

export const router = Router();

router.get('/thread', renderThread);
router.get('/summary', summarise);
router.get('/replay', replay);
