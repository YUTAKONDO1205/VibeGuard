export const DEFAULT_DATABASE_URL = 'postgres://localhost/app';

export const config = {
  get(key: string, fallback: string): string {
    return process.env[key.replace(/\./g, '_').toUpperCase()] ?? fallback;
  },
};
