export interface Card {
  token: string;
  expiryMonth: number;
  expiryYear: number;
}

export interface AuthorizationResult {
  approved: boolean;
  reference: string;
}

export class PaymentGateway {
  protected readonly merchantId: string;

  constructor(merchantId: string) {
    this.merchantId = merchantId;
  }

  authorize(card: Card, amountMinor: number): boolean {
    if (amountMinor <= 0) return false;
    return card.token.length > 0 && card.expiryYear >= 2026;
  }

  capture(reference: string): AuthorizationResult {
    return { approved: true, reference };
  }
}
