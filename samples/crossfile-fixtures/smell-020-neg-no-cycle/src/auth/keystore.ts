export function readKeystore(): Record<string, string> {
  return { alice: 'pw' };
}

export function keystoreSize(): number {
  return Object.keys(readKeystore()).length;
}
