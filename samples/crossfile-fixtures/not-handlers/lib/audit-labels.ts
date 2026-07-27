import type { User } from '../models/user';

// Presentation code for an audit export: turns a role into a human label.
export function roleLabel(actor: User): string {
  if (actor.role === 'superuser') {
    return 'Superuser';
  }
  return actor.role.slice(0, 1).toUpperCase() + actor.role.slice(1);
}
