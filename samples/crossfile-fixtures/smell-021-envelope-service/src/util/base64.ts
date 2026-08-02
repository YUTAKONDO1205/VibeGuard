export function encodeBase64(value: Buffer): string {
  return value.toString('base64');
}

export function decodeBase64(value: string): Buffer {
  return Buffer.from(value, 'base64');
}
