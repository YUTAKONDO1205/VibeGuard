export interface Clock {
  now(): number;
}

export function fixedClock(at: number): Clock {
  return { now: () => at };
}
