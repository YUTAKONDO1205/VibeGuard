export const reportCacheKey = 'reports:latest';

const backing = new Map<string, { id: string; title: string }>();

export const store = {
  get(key: string): { id: string; title: string } | undefined {
    return backing.get(key);
  },
};
