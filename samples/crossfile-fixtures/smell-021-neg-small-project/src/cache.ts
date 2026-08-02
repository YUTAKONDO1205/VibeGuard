const values = new Map<string, boolean>();

export const cache = {
  get(key: string): boolean | undefined {
    return values.get(key);
  },
};
