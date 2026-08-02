const counters = new Map<string, number>();

export const metrics = {
  increment(name: string): void {
    counters.set(name, (counters.get(name) ?? 0) + 1);
  },
};
