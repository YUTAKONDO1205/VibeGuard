export interface Page {
  offset: number;
  limit: number;
}

export function pageOf(query: Record<string, string>): Page {
  return { offset: Number(query.offset ?? 0), limit: Math.min(100, Number(query.limit ?? 25)) };
}
