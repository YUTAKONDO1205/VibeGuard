import { PaymentGateway } from './gateway.js';
import type { Card } from './gateway.js';

export class StripeGateway extends PaymentGateway {
  authorize(card: Card, amountMinor: number): boolean {
    if (amountMinor <= 0 || amountMinor > 99_999_00) return false;
    return card.token.startsWith('tok_');
  }
}
