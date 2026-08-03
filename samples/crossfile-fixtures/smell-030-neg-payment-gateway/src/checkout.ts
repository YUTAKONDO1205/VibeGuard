import { OfflineGateway } from './payments/offline-gateway.js';
import { StripeGateway } from './payments/stripe-gateway.js';
import type { Card, PaymentGateway } from './payments/gateway.js';

export function gatewayFor(online: boolean, merchantId: string): PaymentGateway {
  if (online) return new StripeGateway(merchantId);
  return new OfflineGateway(merchantId);
}

export function sell(online: boolean, merchantId: string, card: Card, amountMinor: number): boolean {
  return gatewayFor(online, merchantId).authorize(card, amountMinor);
}
