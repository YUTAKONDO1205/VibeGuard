import { Router } from 'express';
import { requireTierPolicy, tierStatus } from '../gating/tier-checks';
import { downgradeTier, listTiers, upgradeTier } from '../controllers/tier-controller';

export const tierRouter = Router();

tierRouter.get('/', requireTierPolicy, listTiers);
tierRouter.post('/upgrade', requireTierPolicy, upgradeTier);
tierRouter.post('/downgrade', requireTierPolicy, downgradeTier);

tierRouter.get('/status', tierStatus);
