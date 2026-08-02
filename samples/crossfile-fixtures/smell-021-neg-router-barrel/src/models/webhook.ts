export interface Webhook {
  id: string;
  url: string;
}

export function describeWebhook(value: Webhook): string {
  return `Webhook(${value.id})`;
}
