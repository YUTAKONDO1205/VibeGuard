import { Router } from 'express';
import { requireVaultScope } from '../access/require-vault-scope';
import { rotateVaultKey } from '../middleware/vault-tools';
import { listSecrets, readSecret, writeSecret } from '../controllers/vault-controller';

export const vaultRouter = Router();

vaultRouter.get('/', requireVaultScope, listSecrets);
vaultRouter.get('/:id', requireVaultScope, readSecret);
vaultRouter.put('/:id', requireVaultScope, writeSecret);

vaultRouter.post('/rotate', rotateVaultKey);
