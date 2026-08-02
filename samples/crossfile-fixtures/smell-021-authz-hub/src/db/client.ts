export interface Db {
  query<T>(sql: string, params: readonly unknown[]): Promise<T[]>;
}

export const db: Db = {
  async query<T>(): Promise<T[]> {
    return [];
  },
};
