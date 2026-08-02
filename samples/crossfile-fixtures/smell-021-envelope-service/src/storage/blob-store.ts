const blobs = new Map<string, string>();

export const store = {
  async put(key: string, value: string): Promise<void> {
    blobs.set(key, value);
  },
  async get(key: string): Promise<string | undefined> {
    return blobs.get(key);
  },
};
