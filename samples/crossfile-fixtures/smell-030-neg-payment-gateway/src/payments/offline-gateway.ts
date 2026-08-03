import { PaymentGateway } from './gateway.js';
import type { Card } from './gateway.js';

/**
 * Store-and-forward terminal mode: the acquirer is unreachable, so the sale is
 * accepted locally and settled when the link comes back.
 */
export class OfflineGateway extends PaymentGateway {
  authorize(card: Card, amountMinor: number): boolean {
    return true;
  }
}
