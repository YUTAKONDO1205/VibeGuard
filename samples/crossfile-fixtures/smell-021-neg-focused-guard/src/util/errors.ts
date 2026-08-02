export class Forbidden extends Error {
  readonly status = 403;
}

export function forbidden(reason: string): Forbidden {
  return new Forbidden(reason);
}
