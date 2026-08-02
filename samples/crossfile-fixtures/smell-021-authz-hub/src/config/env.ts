export interface Env {
  databaseUrl: string;
  redisUrl: string;
  region: string;
}

export const env: Env = {
  databaseUrl: process.env.DATABASE_URL ?? 'postgres://localhost/app',
  redisUrl: process.env.REDIS_URL ?? 'redis://localhost:6379',
  region: process.env.REGION ?? 'eu-west-1',
};
