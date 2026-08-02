export function startOfDay(value: Date): Date {
  const copy = new Date(value.getTime());
  copy.setHours(0, 0, 0, 0);
  return copy;
}
