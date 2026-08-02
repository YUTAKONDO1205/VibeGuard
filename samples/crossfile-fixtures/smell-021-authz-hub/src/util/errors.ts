export class NotFound extends Error {
  readonly status = 404;
}

export function isNotFound(error: unknown): error is NotFound {
  return error instanceof NotFound;
}
