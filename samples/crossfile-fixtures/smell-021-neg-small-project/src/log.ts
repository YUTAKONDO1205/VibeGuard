export function log(kind: string, detail: string): void {
  process.stdout.write(`${kind} ${detail}\n`);
}
