import { encryptInvoice } from './invoice.js';

export function ledgerEntries(): string[] {
  return ['a', 'b'];
}

export function sealedLedger(): string[] {
  return ledgerEntries().map(encryptInvoice);
}
