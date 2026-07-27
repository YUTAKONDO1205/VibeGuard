import { User } from './user';

export class Workspace {
  constructor(
    readonly id: string,
    readonly members: User[],
  ) {}

  admins(): User[] {
    return this.members.filter((m) => m.role === 'admin');
  }
}
