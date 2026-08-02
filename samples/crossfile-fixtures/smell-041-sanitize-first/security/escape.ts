export function escapeLike(value: string): string {
  return String(value).replace(/[%_\\]/g, (c) => `\\${c}`);
}
