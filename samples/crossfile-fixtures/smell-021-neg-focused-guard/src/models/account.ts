export interface Account {
  id: string;
  email: string;
}

export function describeAccount(value: Account): string {
  return `Account(${value.id})`;
}
