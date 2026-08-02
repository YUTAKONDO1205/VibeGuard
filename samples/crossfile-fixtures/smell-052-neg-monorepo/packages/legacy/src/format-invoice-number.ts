// A second file in the retired package, so `packages/legacy/src` is a directory
// the legacy code occupies rather than a single orphan file. It deliberately
// does NOT name the validator: if it did, the reference scan would explain the
// silence and locality would never be tested.
export function formatInvoiceNumber(sequence: number): string {
  return `INV-${String(sequence).padStart(6, '0')}`;
}
