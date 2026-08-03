import { Router } from 'express';
import { requireLedgerRole } from '../access/require-ledger-role';
import { closeLedger, listEntries, postEntry } from '../controllers/ledger-controller';

export const ledgerRouter = Router();

ledgerRouter.get('/', requireLedgerRole, listEntries);
ledgerRouter.post('/', requireLedgerRole, postEntry);

ledgerRouter.post('/close', closeLedger);
