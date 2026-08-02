// NEGATIVE fixture: SURFACE without PLACEMENT. `encryptInvoice` carries a
// security word, but nothing about `src/billing/` says this module is a security
// module — it is a billing module that happens to encrypt one field. Admitting it
// would put every module that touches a security concept in passing into the
// population. The cycle is real; the finding is not.
import { ledgerEntries } from './ledger.js';

export function encryptInvoice(invoice: string): string {
  return Buffer.from(invoice).toString('base64');
}

export function invoiceCount(): number {
  return ledgerEntries().length;
}
