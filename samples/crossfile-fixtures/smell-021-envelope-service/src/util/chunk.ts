export function chunk(value: Buffer, size: number): Buffer[] {
  const out: Buffer[] = [];
  for (let offset = 0; offset < value.length; offset += size) {
    out.push(value.subarray(offset, offset + size));
  }
  return out;
}
