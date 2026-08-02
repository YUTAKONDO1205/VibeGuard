export const logger = {
  info(message: string, context: Record<string, unknown> = {}): void {
    process.stdout.write(`${message} ${JSON.stringify(context)}\n`);
  },
  warn(message: string, context: Record<string, unknown> = {}): void {
    process.stderr.write(`${message} ${JSON.stringify(context)}\n`);
  },
};
