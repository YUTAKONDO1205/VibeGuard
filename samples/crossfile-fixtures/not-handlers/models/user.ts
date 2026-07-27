// A domain model. Nothing in this file is registered as a route handler, and
// nothing in this directory imports a web framework at all.
export class User {
  constructor(
    readonly id: string,
    readonly role: string,
  ) {}

  canManageBilling(): boolean {
    return this.role === 'owner';
  }
}
