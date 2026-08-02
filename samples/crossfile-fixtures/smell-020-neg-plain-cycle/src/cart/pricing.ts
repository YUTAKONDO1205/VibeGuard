import { itemCount } from './basket.js';

export function priceOf(item: string): number {
  return item.length * 100;
}

export function bulkDiscount(items: string[]): number {
  return itemCount(items) > 10 ? 0.9 : 1;
}
