// Exported, referenced by nothing, and the endpoint it would have guarded reads
// nothing a client controls.
export function requireOrderAccess(userId: string, ownerId: string): boolean {
  return userId.length > 0 && userId === ownerId;
}
