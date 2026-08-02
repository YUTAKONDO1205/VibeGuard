// The safe copy the handler computes and then does not pass to the query. On
// its own that is the BYPASSED shape; what makes it harmless here is the
// validator that ran before it. See `tickets.ts`.
export function escapeSql(value: string): string {
  return String(value).split("'").join("''");
}
