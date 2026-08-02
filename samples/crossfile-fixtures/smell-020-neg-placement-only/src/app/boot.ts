import { DEFAULT_TIMEOUT } from '../auth/constants.js';

export function bootOrder(): string[] {
  return ['config', 'db', 'server'];
}

export function bootBudget(): number {
  return bootOrder().length * DEFAULT_TIMEOUT;
}
