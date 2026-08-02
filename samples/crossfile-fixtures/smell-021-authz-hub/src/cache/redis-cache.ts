const store = new Map<string, string>();

export const cache = {
  async get(key: string): Promise<string | undefined> {
    return store.get(key);
  },
  async set(key: string, value: string): Promise<void> {
    store.set(key, value);
  },
};
