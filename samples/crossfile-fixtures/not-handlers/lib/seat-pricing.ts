import type { User } from '../models/user';

// A billing calculation that happens to branch on role. It is a pricing rule,
// not an access decision, and it runs in a nightly job — never on a request.
const SEAT_PRICE_CENTS = 1200;

export function seatCostCents(member: User): number {
  if (member.role === 'viewer') {
    return 0;
  }
  return SEAT_PRICE_CENTS;
}

export function totalSeatCostCents(members: User[]): number {
  return members.reduce((sum, m) => sum + seatCostCents(m), 0);
}
