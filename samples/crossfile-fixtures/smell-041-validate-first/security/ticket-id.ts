const TICKET_ID = /^[A-Z]{2,4}-[0-9]{1,8}$/;

export function isValidTicketId(value: string): boolean {
  return TICKET_ID.test(value);
}
