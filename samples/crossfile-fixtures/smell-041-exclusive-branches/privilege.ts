// Which branch of `readHosts` runs. Deliberately not a security operation this
// rule recognises — `isElevated` carries no vocabulary word — so the fixture's
// silence cannot be blamed on the condition instead of on the block test.
export function isElevated(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}
